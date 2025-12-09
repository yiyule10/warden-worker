use std::{collections::HashMap, sync::Arc};

use axum::{
    body::Bytes,
    extract::{Multipart, Path, State},
    Extension, Json,
};
use chrono::Utc;
use jsonwebtoken::{encode, EncodingKey, Header};
use log;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;
use worker::{query, wasm_bindgen::JsValue, Bucket, D1Database, Env, HttpMetadata};

use crate::{
    auth::Claims,
    db,
    error::AppError,
    models::{
        attachment::{AttachmentDB, AttachmentResponse},
        cipher::{Cipher, CipherDBModel},
    },
    BaseUrl,
};

const ATTACHMENTS_BUCKET: &str = "ATTACHMENTS_BUCKET";
const SIZE_LEEWAY_BYTES: i64 = 1024 * 1024; // 1 MiB
const DEFAULT_ATTACHMENT_TTL_SECS: i64 = 300; // 5 minutes

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentCreateRequest {
    pub key: String,
    pub file_name: String,
    pub file_size: NumberOrString,
    #[serde(default)]
    #[allow(dead_code)] // We don't support org features and admin requests
    pub admin_request: Option<bool>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentUploadResponse {
    pub object: String,
    pub attachment_id: String,
    pub url: String,
    pub file_upload_type: i32,
    #[serde(rename = "cipherResponse")]
    pub cipher_response: Cipher,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentDeleteResponse {
    pub cipher: Cipher,
}

#[derive(Deserialize)]
#[serde(untagged)]
pub enum NumberOrString {
    Number(i64),
    String(String),
}

#[derive(Debug, Serialize, Deserialize)]
struct AttachmentDownloadClaims {
    pub sub: String,
    pub cipher_id: String,
    pub attachment_id: String,
    pub exp: usize,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct AttachmentKeyRow {
    cipher_id: String,
    id: String,
}

impl NumberOrString {
    pub fn into_i64(self) -> Result<i64, AppError> {
        match self {
            NumberOrString::Number(v) => Ok(v),
            NumberOrString::String(v) => v
                .parse::<i64>()
                .map_err(|_| AppError::BadRequest("Invalid attachment size".to_string())),
        }
    }
}

async fn touch_cipher_updated_at(db: &D1Database, cipher_id: &str) -> Result<(), AppError> {
    let now = now_string();
    query!(
        db,
        "UPDATE ciphers SET updated_at = ?1 WHERE id = ?2",
        now,
        cipher_id
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;
    Ok(())
}

/// POST /api/ciphers/{cipher_id}/attachment/v2
#[worker::send]
pub async fn create_attachment_v2(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Extension(BaseUrl(base_url)): Extension<BaseUrl>,
    Path(cipher_id): Path<String>,
    Json(payload): Json<AttachmentCreateRequest>,
) -> Result<Json<AttachmentUploadResponse>, AppError> {
    // Require bucket; fail directly if missing
    let _bucket = require_bucket(&env)?;
    let db = db::get_db(&env)?;

    let cipher = ensure_cipher_for_user(&db, &cipher_id, &claims.sub).await?;

    let AttachmentCreateRequest {
        key,
        file_name,
        file_size,
        admin_request: _,
    } = payload;

    let declared_size = file_size.into_i64()?;
    if declared_size <= 0 {
        return Err(AppError::BadRequest(
            "Attachment size must be positive".to_string(),
        ));
    }

    enforce_limits(
        &db,
        &env,
        &claims.sub,
        declared_size,
        None, /* exclude_attachment */
    )
    .await?;

    let attachment_id = Uuid::new_v4().to_string();
    let now = now_string();

    query!(
        &db,
        "INSERT INTO attachments (id, cipher_id, file_name, file_size, akey, created_at, updated_at, organization_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, ?7)",
        attachment_id,
        cipher.id,
        file_name,
        declared_size,
        key,
        now,
        cipher.organization_id,
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    // Return upload URL pointing to local upload endpoint
    let url = upload_url(&env, &base_url, &cipher_id, &attachment_id, &claims.sub)?;
    let mut cipher_response: Cipher = cipher.into();
    hydrate_cipher_attachments(&db, &env, &mut cipher_response).await?;

    touch_cipher_updated_at(&db, &cipher_id).await?;
    db::touch_user_updated_at(&db, &claims.sub).await?;

    Ok(Json(AttachmentUploadResponse {
        object: "attachment-fileUpload".to_string(),
        attachment_id,
        url,
        file_upload_type: 1, // Direct PUT with token
        cipher_response,
    }))
}

/// POST /api/ciphers/{cipher_id}/attachment/{attachment_id}
#[worker::send]
pub async fn upload_attachment_v2_data(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path((cipher_id, attachment_id)): Path<(String, String)>,
    mut multipart: Multipart,
) -> Result<Json<()>, AppError> {
    let bucket = require_bucket(&env)?;
    let db = db::get_db(&env)?;

    let _cipher = ensure_cipher_for_user(&db, &cipher_id, &claims.sub).await?;

    let mut attachment = fetch_attachment(&db, &attachment_id).await?;
    if attachment.cipher_id != cipher_id {
        return Err(AppError::BadRequest(
            "Attachment does not belong to cipher".to_string(),
        ));
    }

    let (file_bytes, content_type, key_override, _file_name) =
        read_multipart(&mut multipart).await?;
    let actual_size = file_bytes.len() as i64;

    // Validate actual size against declared value deviation
    if let Err(e) = validate_size_within_declared(&attachment, actual_size) {
        query!(&db, "DELETE FROM attachments WHERE id = ?1", attachment.id)
            .map_err(|_| AppError::Database)?
            .run()
            .await?;
        return Err(e);
    }

    // Validate capacity limits (replace with actual size)
    enforce_limits(&db, &env, &claims.sub, actual_size, Some(&attachment.id)).await?;

    // Need a key
    if attachment.akey.is_none() && key_override.is_none() {
        return Err(AppError::BadRequest(
            "No attachment key provided".to_string(),
        ));
    }
    if let Some(k) = key_override {
        attachment.akey = Some(k);
    }

    // Save to R2
    upload_to_r2(
        &bucket,
        &attachment.r2_key(),
        content_type,
        file_bytes.to_vec(),
    )
    .await?;

    // Update metadata
    let now = now_string();
    query!(
        &db,
        "UPDATE attachments SET file_size = ?1, akey = COALESCE(?2, akey), updated_at = ?3 WHERE id = ?4",
        actual_size,
        attachment.akey,
        now,
        attachment.id,
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    touch_cipher_updated_at(&db, &cipher_id).await?;
    db::touch_user_updated_at(&db, &claims.sub).await?;

    Ok(Json(()))
}

/// POST /api/ciphers/{cipher_id}/attachment
/// Legacy API for creating an attachment associated with a cipher.
#[worker::send]
pub async fn upload_attachment_legacy(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(cipher_id): Path<String>,
    mut multipart: Multipart,
) -> Result<Json<Cipher>, AppError> {
    let bucket = require_bucket(&env)?;
    let db = db::get_db(&env)?;

    let cipher = ensure_cipher_for_user(&db, &cipher_id, &claims.sub).await?;

    let (file_bytes, content_type, key, file_name) = read_multipart(&mut multipart).await?;
    let key = key.ok_or_else(|| AppError::BadRequest("No attachment key provided".to_string()))?;
    let file_name =
        file_name.ok_or_else(|| AppError::BadRequest("No filename provided".to_string()))?;

    let actual_size = file_bytes.len() as i64;
    if actual_size <= 0 {
        return Err(AppError::BadRequest(
            "Attachment size must be positive".to_string(),
        ));
    }

    // Validate capacity limits
    enforce_limits(&db, &env, &claims.sub, actual_size, None).await?;

    let attachment_id = Uuid::new_v4().to_string();
    let now = now_string();

    query!(
        &db,
        "INSERT INTO attachments (id, cipher_id, file_name, file_size, akey, created_at, updated_at, organization_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, ?7)",
        attachment_id,
        cipher.id,
        file_name,
        actual_size,
        key,
        now,
        cipher.organization_id,
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    // Save to R2
    upload_to_r2(
        &bucket,
        &format!("{}/{}", cipher_id, attachment_id),
        content_type,
        file_bytes.to_vec(),
    )
    .await?;

    touch_cipher_updated_at(&db, &cipher_id).await?;
    db::touch_user_updated_at(&db, &claims.sub).await?;

    // 返回最新的 Cipher（含附件）
    let mut cipher_response: Cipher = cipher.into();
    hydrate_cipher_attachments(&db, &env, &mut cipher_response).await?;

    Ok(Json(cipher_response))
}

/// GET /api/ciphers/{cipher_id}/attachment/{attachment_id}
#[worker::send]
pub async fn get_attachment(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Extension(BaseUrl(base_url)): Extension<BaseUrl>,
    Path((cipher_id, attachment_id)): Path<(String, String)>,
) -> Result<Json<AttachmentResponse>, AppError> {
    let _bucket = require_bucket(&env)?;
    let db = db::get_db(&env)?;

    let cipher = ensure_cipher_for_user(&db, &cipher_id, &claims.sub).await?;
    let attachment = fetch_attachment(&db, &attachment_id).await?;

    if attachment.cipher_id != cipher.id {
        return Err(AppError::BadRequest(
            "Attachment does not belong to cipher".to_string(),
        ));
    }

    let url = download_url(&env, &base_url, &cipher_id, &attachment_id, &claims.sub)?;
    Ok(Json(attachment.to_response(Some(url))))
}

/// DELETE /api/ciphers/{cipher_id}/attachment/{attachment_id}
#[worker::send]
pub async fn delete_attachment(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path((cipher_id, attachment_id)): Path<(String, String)>,
) -> Result<Json<AttachmentDeleteResponse>, AppError> {
    let bucket = require_bucket(&env)?;
    let db = db::get_db(&env)?;

    let cipher = ensure_cipher_for_user(&db, &cipher_id, &claims.sub).await?;
    let attachment = fetch_attachment(&db, &attachment_id).await?;

    if attachment.cipher_id != cipher.id {
        return Err(AppError::BadRequest(
            "Attachment does not belong to cipher".to_string(),
        ));
    }

    // Delete R2 object; ignore missing objects
    delete_r2_objects(&bucket, &[attachment.r2_key()]).await?;

    query!(&db, "DELETE FROM attachments WHERE id = ?1", attachment.id)
        .map_err(|_| AppError::Database)?
        .run()
        .await?;

    touch_cipher_updated_at(&db, &cipher_id).await?;
    db::touch_user_updated_at(&db, &claims.sub).await?;

    // Reload cipher to return fresh updated_at and attachments state
    let mut cipher_response: Cipher = ensure_cipher_for_user(&db, &cipher_id, &claims.sub)
        .await?
        .into();
    hydrate_cipher_attachments(&db, &env, &mut cipher_response).await?;

    Ok(Json(AttachmentDeleteResponse {
        cipher: cipher_response,
    }))
}

/// POST /api/ciphers/{cipher_id}/attachment/{attachment_id}/delete
/// Legacy API for deleting an attachment associated with a cipher.
#[worker::send]
pub async fn delete_attachment_post(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path((cipher_id, attachment_id)): Path<(String, String)>,
) -> Result<Json<AttachmentDeleteResponse>, AppError> {
    delete_attachment(claims, State(env), Path((cipher_id, attachment_id))).await
}

/// Attach attachment information to Cipher (used by other handlers)
pub async fn hydrate_cipher_attachments(
    db: &D1Database,
    env: &Env,
    cipher: &mut Cipher,
) -> Result<(), AppError> {
    if !attachments_enabled(env) {
        cipher.attachments = None;
        return Ok(());
    }

    let mut map = load_attachment_map(db, &[cipher.id.clone()]).await?;
    if let Some(list) = map.remove(&cipher.id) {
        if !list.is_empty() {
            cipher.attachments = Some(list);
        }
    }
    Ok(())
}

/// Batch attach attachments to multiple Ciphers
pub async fn hydrate_ciphers_attachments(
    db: &D1Database,
    env: &Env,
    ciphers: &mut [Cipher],
) -> Result<(), AppError> {
    if !attachments_enabled(env) {
        for cipher in ciphers.iter_mut() {
            cipher.attachments = None;
        }
        return Ok(());
    }

    let ids: Vec<String> = ciphers.iter().map(|c| c.id.clone()).collect();
    let mut map = load_attachment_map(db, &ids).await?;

    for cipher in ciphers.iter_mut() {
        if let Some(list) = map.remove(&cipher.id) {
            if !list.is_empty() {
                cipher.attachments = Some(list);
            }
        }
    }

    Ok(())
}

pub(crate) fn attachments_enabled(env: &Env) -> bool {
    env.bucket(ATTACHMENTS_BUCKET).is_ok()
}

pub(crate) fn require_bucket(env: &Env) -> Result<Bucket, AppError> {
    env.bucket(ATTACHMENTS_BUCKET)
        .map_err(|_| AppError::BadRequest("Attachments are not enabled".to_string()))
}

fn is_not_found_error(err: &worker::Error) -> bool {
    let msg = err.to_string();
    msg.contains("NoSuchKey") || msg.contains("404") || msg.contains("NotFound")
}

pub(crate) async fn delete_r2_objects(bucket: &Bucket, keys: &[String]) -> Result<(), AppError> {
    for key in keys {
        if let Err(err) = bucket.delete(key).await {
            if !is_not_found_error(&err) {
                return Err(AppError::Worker(err));
            }
        }
    }
    Ok(())
}

fn map_rows_to_keys(rows: Vec<AttachmentKeyRow>) -> Vec<String> {
    rows.into_iter()
        .map(|row| format!("{}/{}", row.cipher_id, row.id))
        .collect()
}

pub(crate) async fn list_attachment_keys_for_cipher_ids(
    db: &D1Database,
    cipher_ids: &[String],
    user_id: Option<&str>,
) -> Result<Vec<String>, AppError> {
    if cipher_ids.is_empty() {
        return Ok(Vec::new());
    }

    let ids_json = serde_json::to_string(cipher_ids).map_err(|_| AppError::Internal)?;

    let mut sql = "SELECT a.cipher_id, a.id FROM attachments a JOIN ciphers c ON a.cipher_id = c.id WHERE c.id IN (SELECT value FROM json_each(?1))".to_string();
    let mut params: Vec<worker::wasm_bindgen::JsValue> = vec![ids_json.into()];

    if let Some(uid) = user_id {
        sql.push_str(" AND c.user_id = ?2");
        params.push(uid.into());
    }

    let rows: Vec<AttachmentKeyRow> = db
        .prepare(&sql)
        .bind(&params)?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()
        .map_err(|_| AppError::Database)?;

    Ok(map_rows_to_keys(rows))
}

pub(crate) async fn list_attachment_keys_for_user(
    db: &D1Database,
    user_id: &str,
) -> Result<Vec<String>, AppError> {
    let rows: Vec<AttachmentKeyRow> = db
        .prepare(
            "SELECT a.cipher_id, a.id FROM attachments a \
             JOIN ciphers c ON a.cipher_id = c.id \
             WHERE c.user_id = ?1",
        )
        .bind(&[user_id.into()])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()
        .map_err(|_| AppError::Database)?;

    Ok(map_rows_to_keys(rows))
}

pub(crate) async fn list_attachment_keys_for_soft_deleted_before(
    db: &D1Database,
    cutoff_exclusive: &str,
) -> Result<Vec<String>, AppError> {
    let rows: Vec<AttachmentKeyRow> = db
        .prepare(
            "SELECT a.cipher_id, a.id FROM attachments a \
             JOIN ciphers c ON a.cipher_id = c.id \
             WHERE c.deleted_at IS NOT NULL AND c.deleted_at < ?1",
        )
        .bind(&[cutoff_exclusive.into()])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()
        .map_err(|_| AppError::Database)?;

    Ok(map_rows_to_keys(rows))
}

fn download_url(
    env: &Env,
    base_url: &str,
    cipher_id: &str,
    attachment_id: &str,
    user_id: &str,
) -> Result<String, AppError> {
    let token = build_download_token(env, user_id, cipher_id, attachment_id)?;
    let normalized_base = base_url.trim_end_matches('/');
    Ok(format!(
        "{normalized_base}/api/ciphers/{cipher_id}/attachment/{attachment_id}/download?token={token}"
    ))
}

fn now_string() -> String {
    Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

async fn ensure_cipher_for_user(
    db: &D1Database,
    cipher_id: &str,
    user_id: &str,
) -> Result<CipherDBModel, AppError> {
    let cipher: Option<CipherDBModel> = db
        .prepare("SELECT * FROM ciphers WHERE id = ?1 AND user_id = ?2")
        .bind(&[cipher_id.into(), user_id.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;

    let cipher = cipher.ok_or_else(|| AppError::NotFound("Cipher not found".to_string()))?;

    if cipher.organization_id.is_some() {
        return Err(AppError::BadRequest(
            "Organization attachments are not supported".to_string(),
        ));
    }

    if cipher.deleted_at.is_some() {
        return Err(AppError::BadRequest("Cipher is deleted".to_string()));
    }

    Ok(cipher)
}

async fn fetch_attachment(db: &D1Database, attachment_id: &str) -> Result<AttachmentDB, AppError> {
    db.prepare("SELECT * FROM attachments WHERE id = ?1")
        .bind(&[attachment_id.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::NotFound("Attachment not found".to_string()))
}

async fn load_attachment_map(
    db: &D1Database,
    cipher_ids: &[String],
) -> Result<HashMap<String, Vec<AttachmentResponse>>, AppError> {
    if cipher_ids.is_empty() {
        return Ok(HashMap::new());
    }

    let ids_json = serde_json::to_string(cipher_ids).map_err(|_| AppError::Internal)?;

    let attachments: Vec<AttachmentDB> = db
        .prepare("SELECT * FROM attachments WHERE cipher_id IN (SELECT value FROM json_each(?1))")
        .bind(&[ids_json.into()])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()
        .map_err(|_| AppError::Database)?;

    let mut map: HashMap<String, Vec<AttachmentResponse>> = HashMap::new();

    for attachment in attachments {
        map.entry(attachment.cipher_id.clone())
            .or_default()
            // URLs are minted on-demand via the download endpoint; skip pre-signing here.
            .push(attachment.to_response(None));
    }

    Ok(map)
}

async fn upload_to_r2(
    bucket: &Bucket,
    key: &str,
    content_type: Option<String>,
    data: Vec<u8>,
) -> Result<(), AppError> {
    let mut builder = bucket.put(key, data);

    if let Some(ct) = content_type {
        builder = builder.http_metadata(HttpMetadata {
            content_type: Some(ct),
            ..Default::default()
        });
    }

    builder.execute().await.map_err(AppError::Worker)?;
    Ok(())
}

async fn read_multipart(
    multipart: &mut Multipart,
) -> Result<(Bytes, Option<String>, Option<String>, Option<String>), AppError> {
    let mut file_bytes: Option<Bytes> = None;
    let mut content_type: Option<String> = None;
    let mut key: Option<String> = None;
    let mut file_name: Option<String> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| AppError::BadRequest("Invalid multipart data".to_string()))?
    {
        match field.name() {
            Some("data") => {
                content_type = field.content_type().map(|s| s.to_string());
                file_name = field.file_name().map(|s| s.to_string());
                file_bytes =
                    Some(field.bytes().await.map_err(|_| {
                        AppError::BadRequest("Failed to read file data".to_string())
                    })?);
            }
            Some("key") => {
                key = Some(
                    field
                        .text()
                        .await
                        .map_err(|_| AppError::BadRequest("Invalid key field".to_string()))?,
                );
            }
            _ => {}
        }
    }

    let file_bytes = file_bytes
        .ok_or_else(|| AppError::BadRequest("No attachment data provided".to_string()))?;

    Ok((file_bytes, content_type, key, file_name))
}

fn validate_size_within_declared(
    attachment: &AttachmentDB,
    actual_size: i64,
) -> Result<(), AppError> {
    let max_size = attachment
        .file_size
        .checked_add(SIZE_LEEWAY_BYTES)
        .ok_or_else(|| AppError::BadRequest("Attachment size overflow".to_string()))?;
    let min_size = attachment
        .file_size
        .checked_sub(SIZE_LEEWAY_BYTES)
        .ok_or_else(|| AppError::BadRequest("Attachment size overflow".to_string()))?;

    if actual_size < min_size || actual_size > max_size {
        return Err(AppError::BadRequest(format!(
            "Attachment size mismatch (expected within [{min_size}, {max_size}], got {actual_size})"
        )));
    }

    Ok(())
}

fn build_download_token(
    env: &Env,
    user_id: &str,
    cipher_id: &str,
    attachment_id: &str,
) -> Result<String, AppError> {
    let ttl_secs = download_ttl_secs(env)?;
    let now = Utc::now().timestamp();
    let exp = now
        .checked_add(ttl_secs)
        .ok_or_else(|| AppError::Internal)?;

    if exp < 0 {
        log::error!(
            "Computed negative expiration for attachment token: cipher={}, attachment={}",
            cipher_id,
            attachment_id
        );
        return Err(AppError::Internal);
    }

    let claims = AttachmentDownloadClaims {
        sub: user_id.to_string(),
        cipher_id: cipher_id.to_string(),
        attachment_id: attachment_id.to_string(),
        exp: exp as usize,
    };

    let secret = jwt_secret(env)?;
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(AppError::from)
}

fn upload_url(
    env: &Env,
    base_url: &str,
    cipher_id: &str,
    attachment_id: &str,
    user_id: &str,
) -> Result<String, AppError> {
    let token = build_download_token(env, user_id, cipher_id, attachment_id)?;
    let normalized_base = base_url.trim_end_matches('/');
    Ok(format!(
        "{normalized_base}/api/ciphers/{cipher_id}/attachment/{attachment_id}/azure-upload?token={token}"
    ))
}

fn jwt_secret(env: &Env) -> Result<String, AppError> {
    Ok(env.secret("JWT_SECRET")?.to_string())
}

fn download_ttl_secs(env: &Env) -> Result<i64, AppError> {
    match env.var("ATTACHMENT_TTL_SECS") {
        Ok(v) => {
            let raw = v.to_string();
            let ttl = raw.parse::<i64>().map_err(|err| {
                log::error!("Invalid ATTACHMENT_TTL_SECS '{}': {}", raw, err);
                AppError::Internal
            })?;

            if ttl <= 0 {
                log::error!("ATTACHMENT_TTL_SECS '{}' must be positive", raw);
                return Err(AppError::Internal);
            }

            Ok(ttl)
        }
        Err(_) => Ok(DEFAULT_ATTACHMENT_TTL_SECS),
    }
}

async fn enforce_limits(
    db: &D1Database,
    env: &Env,
    user_id: &str,
    new_size: i64,
    exclude_attachment: Option<&str>,
) -> Result<(), AppError> {
    if new_size < 0 {
        return Err(AppError::BadRequest(
            "Attachment size cannot be negative".to_string(),
        ));
    }

    let max_bytes = attachment_max_bytes(env)?;
    if let Some(max_bytes) = max_bytes {
        if new_size as u64 > max_bytes {
            return Err(AppError::BadRequest(
                "Attachment size exceeds limit".to_string(),
            ));
        }
    }

    let limit_bytes = total_limit_bytes(env)?;
    if let Some(limit_bytes) = limit_bytes {
        let used = user_attachment_usage(db, user_id, exclude_attachment).await?;
        let limit = limit_bytes as i64;
        let new_total = used
            .checked_add(new_size)
            .ok_or_else(|| AppError::BadRequest("Attachment size overflow".to_string()))?;

        if new_total > limit {
            return Err(AppError::BadRequest(
                "Attachment storage limit reached".to_string(),
            ));
        }
    }

    Ok(())
}

fn attachment_max_bytes(env: &Env) -> Result<Option<u64>, AppError> {
    match env.var("ATTACHMENT_MAX_BYTES") {
        Ok(v) => {
            let raw = v.to_string();
            raw.parse::<u64>().map(Some).map_err(|err| {
                log::error!("Invalid ATTACHMENT_MAX_BYTES '{}': {}", raw, err);
                AppError::Internal
            })
        }
        Err(_) => Ok(None),
    }
}

fn total_limit_bytes(env: &Env) -> Result<Option<u64>, AppError> {
    match env.var("ATTACHMENT_TOTAL_LIMIT_KB") {
        Ok(v) => {
            let raw = v.to_string();
            let kb = raw.parse::<u64>().map_err(|err| {
                log::error!("Invalid ATTACHMENT_TOTAL_LIMIT_KB '{}': {}", raw, err);
                AppError::Internal
            })?;

            let bytes = kb.checked_mul(1024).ok_or_else(|| {
                log::error!(
                    "ATTACHMENT_TOTAL_LIMIT_KB '{}' overflowed when converting to bytes",
                    raw
                );
                AppError::Internal
            })?;

            Ok(Some(bytes))
        }
        Err(_) => Ok(None),
    }
}

async fn user_attachment_usage(
    db: &D1Database,
    user_id: &str,
    exclude_attachment: Option<&str>,
) -> Result<i64, AppError> {
    let query_str = if exclude_attachment.is_some() {
        "SELECT COALESCE(SUM(a.file_size), 0) as total
         FROM attachments a
         JOIN ciphers c ON c.id = a.cipher_id
         WHERE c.user_id = ?1 AND a.id != ?2"
    } else {
        "SELECT COALESCE(SUM(a.file_size), 0) as total
         FROM attachments a
         JOIN ciphers c ON c.id = a.cipher_id
         WHERE c.user_id = ?1"
    };

    let mut bindings: Vec<JsValue> = vec![JsValue::from_str(user_id)];
    if let Some(id) = exclude_attachment {
        bindings.push(JsValue::from_str(id));
    }

    let row: Option<Value> = db
        .prepare(query_str)
        .bind(&bindings)?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;

    let total = row
        .and_then(|v| v.get("total").cloned())
        .and_then(|v| v.as_i64())
        .unwrap_or(0);

    Ok(total)
}
