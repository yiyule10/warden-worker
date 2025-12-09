use super::get_batch_size;
use axum::{extract::State, Extension, Json};
use chrono::{DateTime, Utc};
use log; // Used for warning logs on parse failures
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;
use worker::{query, D1PreparedStatement, Env};

use crate::auth::Claims;
use crate::db;
use crate::error::AppError;
use crate::handlers::attachments;
use crate::models::cipher::{
    Cipher, CipherDBModel, CipherData, CipherListResponse, CipherRequestData, CreateCipherRequest,
    MoveCipherData, PartialCipherData,
};
use crate::models::user::{PasswordOrOtpData, User};
use crate::BaseUrl;
use axum::extract::Path;

/// Helper to fetch a cipher by id for a user or return NotFound.
async fn fetch_cipher_for_user(
    db: &worker::D1Database,
    cipher_id: &str,
    user_id: &str,
) -> Result<CipherDBModel, AppError> {
    db.prepare("SELECT * FROM ciphers WHERE id = ?1 AND user_id = ?2")
        .bind(&[cipher_id.to_string().into(), user_id.to_string().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::NotFound("Cipher not found".to_string()))
}

#[worker::send]
pub async fn create_cipher(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<CreateCipherRequest>,
) -> Result<Json<Cipher>, AppError> {
    let db = db::get_db(&env)?;
    let now = Utc::now();
    let now = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    let cipher_data_req = payload.cipher;

    let cipher_data = CipherData {
        name: cipher_data_req.name,
        notes: cipher_data_req.notes,
        type_fields: cipher_data_req.type_fields,
    };

    let data_value = serde_json::to_value(&cipher_data).map_err(|_| AppError::Internal)?;

    let mut cipher = Cipher {
        id: Uuid::new_v4().to_string(),
        user_id: Some(claims.sub.clone()),
        organization_id: cipher_data_req.organization_id.clone(),
        r#type: cipher_data_req.r#type,
        data: data_value,
        favorite: cipher_data_req.favorite.unwrap_or(false),
        folder_id: cipher_data_req.folder_id.clone(),
        deleted_at: None,
        created_at: now.clone(),
        updated_at: now.clone(),
        object: "cipher".to_string(),
        organization_use_totp: false,
        edit: true,
        view_password: true,
        collection_ids: if payload.collection_ids.is_empty() {
            None
        } else {
            Some(payload.collection_ids)
        },
        attachments: None,
    };

    let data = serde_json::to_string(&cipher.data).map_err(|_| AppError::Internal)?;

    query!(
        &db,
        "INSERT INTO ciphers (id, user_id, organization_id, type, data, favorite, folder_id, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
         cipher.id,
         cipher.user_id,
         cipher.organization_id,
         cipher.r#type,
         data,
         cipher.favorite,

         cipher.folder_id,
         cipher.created_at,
         cipher.updated_at,
    ).map_err(|_|AppError::Database)?
    .run()
    .await?;

    attachments::hydrate_cipher_attachments(&db, env.as_ref(), &mut cipher).await?;
    db::touch_user_updated_at(&db, &claims.sub).await?;

    Ok(Json(cipher))
}

#[worker::send]
pub async fn update_cipher(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Extension(BaseUrl(_base_url)): Extension<BaseUrl>,
    Path(id): Path<String>,
    Json(payload): Json<CipherRequestData>,
) -> Result<Json<Cipher>, AppError> {
    let db = db::get_db(&env)?;
    let now = Utc::now();
    let now = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    let existing_cipher: crate::models::cipher::CipherDBModel = query!(
        &db,
        "SELECT * FROM ciphers WHERE id = ?1 AND user_id = ?2",
        id,
        claims.sub
    )
    .map_err(|_| AppError::Database)?
    .first(None)
    .await?
    .ok_or(AppError::NotFound("Cipher not found".to_string()))?;

    // Validate folder ownership if provided
    if let Some(ref folder_id) = payload.folder_id {
        let folder_exists: Option<serde_json::Value> = db
            .prepare("SELECT id FROM folders WHERE id = ?1 AND user_id = ?2")
            .bind(&[folder_id.clone().into(), claims.sub.clone().into()])?
            .first(None)
            .await?;

        if folder_exists.is_none() {
            return Err(AppError::BadRequest(
                "Invalid folder: Folder does not exist or belongs to another user".to_string(),
            ));
        }
    }

    // Reject updates based on stale client data when the last known revision is provided
    if let Some(dt) = payload.last_known_revision_date.as_deref() {
        match DateTime::parse_from_rfc3339(dt) {
            Ok(client_dt) => match DateTime::parse_from_rfc3339(&existing_cipher.updated_at) {
                Ok(server_dt) => {
                    if server_dt.signed_duration_since(client_dt).num_seconds() > 1 {
                        return Err(AppError::BadRequest(
                            "The client copy of this cipher is out of date. Resync the client and try again.".to_string(),
                        ));
                    }
                }
                Err(err) => log::warn!(
                    "Error parsing server revisionDate '{}' for cipher {}: {}",
                    existing_cipher.updated_at,
                    existing_cipher.id,
                    err
                ),
            },
            Err(err) => log::warn!("Error parsing lastKnownRevisionDate '{}': {}", dt, err),
        }
    }

    let cipher_data_req = payload;

    let cipher_data = CipherData {
        name: cipher_data_req.name,
        notes: cipher_data_req.notes,
        type_fields: cipher_data_req.type_fields,
    };

    let data_value = serde_json::to_value(&cipher_data).map_err(|_| AppError::Internal)?;

    let mut cipher = Cipher {
        id: id.clone(),
        user_id: Some(claims.sub.clone()),
        organization_id: cipher_data_req.organization_id.clone(),
        r#type: cipher_data_req.r#type,
        data: data_value,
        favorite: cipher_data_req.favorite.unwrap_or(false),
        folder_id: cipher_data_req.folder_id.clone(),
        deleted_at: None,
        created_at: existing_cipher.created_at,
        updated_at: now.clone(),
        object: "cipher".to_string(),
        organization_use_totp: false,
        edit: true,
        view_password: true,
        collection_ids: None,
        attachments: None,
    };

    let data = serde_json::to_string(&cipher.data).map_err(|_| AppError::Internal)?;

    query!(
        &db,
        "UPDATE ciphers SET organization_id = ?1, type = ?2, data = ?3, favorite = ?4, folder_id = ?5, updated_at = ?6 WHERE id = ?7 AND user_id = ?8",
        cipher.organization_id,
        cipher.r#type,
        data,
        cipher.favorite,
        cipher.folder_id,
        cipher.updated_at,
        id,
        claims.sub,
    ).map_err(|_|AppError::Database)?
    .run()
    .await?;

    attachments::hydrate_cipher_attachments(&db, env.as_ref(), &mut cipher).await?;
    db::touch_user_updated_at(&db, &claims.sub).await?;

    Ok(Json(cipher))
}

/// GET /api/ciphers - list all non-trashed ciphers for current user
#[worker::send]
pub async fn list_ciphers(
    claims: Claims,
    State(env): State<Arc<Env>>,
) -> Result<Json<CipherListResponse>, AppError> {
    let db = db::get_db(&env)?;

    let ciphers_db: Vec<CipherDBModel> = db
        .prepare(
            "SELECT * FROM ciphers 
             WHERE user_id = ?1 AND deleted_at IS NULL 
             ORDER BY updated_at DESC",
        )
        .bind(&[claims.sub.clone().into()])?
        .all()
        .await?
        .results()?;

    let mut ciphers: Vec<Cipher> = ciphers_db.into_iter().map(|c| c.into()).collect();

    attachments::hydrate_ciphers_attachments(&db, env.as_ref(), &mut ciphers).await?;

    Ok(Json(CipherListResponse {
        data: ciphers,
        object: "list".to_string(),
        continuation_token: None,
    }))
}

/// GET /api/ciphers/{id}
#[worker::send]
pub async fn get_cipher(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(id): Path<String>,
) -> Result<Json<Cipher>, AppError> {
    let db = db::get_db(&env)?;
    let cipher = fetch_cipher_for_user(&db, &id, &claims.sub).await?;
    let mut cipher: Cipher = cipher.into();

    attachments::hydrate_cipher_attachments(&db, env.as_ref(), &mut cipher).await?;

    Ok(Json(cipher))
}

/// GET /api/ciphers/{id}/details
#[worker::send]
pub async fn get_cipher_details(
    claims: Claims,
    state: State<Arc<Env>>,
    id: Path<String>,
) -> Result<Json<Cipher>, AppError> {
    get_cipher(claims, state, id).await
}

/// PUT/POST /api/ciphers/{id}/partial
#[worker::send]
pub async fn update_cipher_partial(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(id): Path<String>,
    Json(payload): Json<PartialCipherData>,
) -> Result<Json<Cipher>, AppError> {
    let db = db::get_db(&env)?;
    let user_id = &claims.sub;

    // Validate folder ownership if provided
    if let Some(ref folder_id) = payload.folder_id {
        let folder_exists: Option<serde_json::Value> = db
            .prepare("SELECT id FROM folders WHERE id = ?1 AND user_id = ?2")
            .bind(&[folder_id.clone().into(), user_id.clone().into()])?
            .first(None)
            .await?;

        if folder_exists.is_none() {
            return Err(AppError::BadRequest(
                "Invalid folder: Folder does not exist or belongs to another user".to_string(),
            ));
        }
    }

    // Ensure cipher exists and belongs to user
    fetch_cipher_for_user(&db, &id, user_id).await?;

    let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    query!(
        &db,
        "UPDATE ciphers SET folder_id = ?1, favorite = ?2, updated_at = ?3 WHERE id = ?4 AND user_id = ?5",
        payload.folder_id,
        payload.favorite,
        now,
        id,
        user_id,
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    db::touch_user_updated_at(&db, user_id).await?;

    let cipher = fetch_cipher_for_user(&db, &id, user_id).await?;
    let mut cipher: Cipher = cipher.into();

    attachments::hydrate_cipher_attachments(&db, env.as_ref(), &mut cipher).await?;

    Ok(Json(cipher))
}

/// Request body for bulk cipher operations
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CipherIdsData {
    pub ids: Vec<String>,
}

/// Soft delete a single cipher (PUT /api/ciphers/{id}/delete)
/// Sets deleted_at to current timestamp
#[worker::send]
pub async fn soft_delete_cipher(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(id): Path<String>,
) -> Result<Json<()>, AppError> {
    let db = db::get_db(&env)?;
    let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    query!(
        &db,
        "UPDATE ciphers SET deleted_at = ?1, updated_at = ?1 WHERE id = ?2 AND user_id = ?3",
        now,
        id,
        claims.sub
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    db::touch_user_updated_at(&db, &claims.sub).await?;

    Ok(Json(()))
}

/// Soft delete multiple ciphers (PUT /api/ciphers/delete)
#[worker::send]
pub async fn soft_delete_ciphers_bulk(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<CipherIdsData>,
) -> Result<Json<()>, AppError> {
    let db = db::get_db(&env)?;
    let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    let batch_size = get_batch_size(&env);
    let mut statements: Vec<D1PreparedStatement> = Vec::with_capacity(payload.ids.len());

    for id in payload.ids {
        let stmt = query!(
            &db,
            "UPDATE ciphers SET deleted_at = ?1, updated_at = ?1 WHERE id = ?2 AND user_id = ?3",
            now,
            id,
            claims.sub
        )
        .map_err(|_| AppError::Database)?;

        statements.push(stmt);
    }

    db::execute_in_batches(&db, statements, batch_size).await?;

    db::touch_user_updated_at(&db, &claims.sub).await?;

    Ok(Json(()))
}

/// Hard delete a single cipher (DELETE /api/ciphers/{id} or POST /api/ciphers/{id}/delete)
/// Permanently removes the cipher from database
#[worker::send]
pub async fn hard_delete_cipher(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(id): Path<String>,
) -> Result<Json<()>, AppError> {
    let db = db::get_db(&env)?;

    if attachments::attachments_enabled(env.as_ref()) {
        let bucket = attachments::require_bucket(env.as_ref())?;
        let keys =
            attachments::list_attachment_keys_for_cipher_ids(&db, &[id.clone()], Some(&claims.sub))
                .await?;
        attachments::delete_r2_objects(&bucket, &keys).await?;
    }

    query!(
        &db,
        "DELETE FROM ciphers WHERE id = ?1 AND user_id = ?2",
        id,
        claims.sub
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    db::touch_user_updated_at(&db, &claims.sub).await?;

    Ok(Json(()))
}

/// Hard delete multiple ciphers (DELETE /api/ciphers or POST /api/ciphers/delete)
#[worker::send]
pub async fn hard_delete_ciphers_bulk(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<CipherIdsData>,
) -> Result<Json<()>, AppError> {
    let db = db::get_db(&env)?;
    let batch_size = get_batch_size(&env);
    let ids = payload.ids;

    if attachments::attachments_enabled(env.as_ref()) {
        let bucket = attachments::require_bucket(env.as_ref())?;
        let keys =
            attachments::list_attachment_keys_for_cipher_ids(&db, &ids, Some(&claims.sub)).await?;
        attachments::delete_r2_objects(&bucket, &keys).await?;
    }

    let mut statements: Vec<D1PreparedStatement> = Vec::with_capacity(ids.len());

    for id in ids {
        let stmt = query!(
            &db,
            "DELETE FROM ciphers WHERE id = ?1 AND user_id = ?2",
            id,
            claims.sub
        )
        .map_err(|_| AppError::Database)?;

        statements.push(stmt);
    }

    db::execute_in_batches(&db, statements, batch_size).await?;

    db::touch_user_updated_at(&db, &claims.sub).await?;

    Ok(Json(()))
}

/// Restore a single cipher (PUT /api/ciphers/{id}/restore)
/// Clears the deleted_at timestamp
#[worker::send]
pub async fn restore_cipher(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(id): Path<String>,
) -> Result<Json<Cipher>, AppError> {
    let db = db::get_db(&env)?;
    let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    // Update the cipher to clear deleted_at
    query!(
        &db,
        "UPDATE ciphers SET deleted_at = NULL, updated_at = ?1 WHERE id = ?2 AND user_id = ?3",
        now,
        id,
        claims.sub
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    // Fetch and return the restored cipher
    let cipher_db: crate::models::cipher::CipherDBModel = query!(
        &db,
        "SELECT * FROM ciphers WHERE id = ?1 AND user_id = ?2",
        id,
        claims.sub
    )
    .map_err(|_| AppError::Database)?
    .first(None)
    .await?
    .ok_or(AppError::NotFound("Cipher not found".to_string()))?;

    let mut cipher: Cipher = cipher_db.into();
    attachments::hydrate_cipher_attachments(&db, env.as_ref(), &mut cipher).await?;

    db::touch_user_updated_at(&db, &claims.sub).await?;

    Ok(Json(cipher))
}

/// Response for bulk restore operation
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkRestoreResponse {
    pub data: Vec<Cipher>,
    pub object: String,
    pub continuation_token: Option<String>,
}

/// Restore multiple ciphers (PUT /api/ciphers/restore)
#[worker::send]
pub async fn restore_ciphers_bulk(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<CipherIdsData>,
) -> Result<Json<BulkRestoreResponse>, AppError> {
    let db = db::get_db(&env)?;
    let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    let batch_size = get_batch_size(&env);
    let ids = payload.ids;

    if ids.is_empty() {
        return Ok(Json(BulkRestoreResponse {
            data: vec![],
            object: "list".to_string(),
            continuation_token: None,
        }));
    }

    // Batch UPDATE operations
    let mut update_statements: Vec<D1PreparedStatement> = Vec::with_capacity(ids.len());
    for id in ids.iter() {
        let stmt = query!(
            &db,
            "UPDATE ciphers SET deleted_at = NULL, updated_at = ?1 WHERE id = ?2 AND user_id = ?3",
            now,
            id.clone(),
            claims.sub
        )
        .map_err(|_| AppError::Database)?;

        update_statements.push(stmt);
    }
    db::execute_in_batches(&db, update_statements, batch_size).await?;

    // Batch SELECT using json_each() - avoid N+1 query problem
    let ids_json = serde_json::to_string(&ids).map_err(|_| AppError::Internal)?;

    let mut restored_ciphers: Vec<Cipher> = db
        .prepare(
            "SELECT * FROM ciphers WHERE user_id = ?1 AND id IN (SELECT value FROM json_each(?2))",
        )
        .bind(&[claims.sub.clone().into(), ids_json.into()])?
        .all()
        .await?
        .results::<crate::models::cipher::CipherDBModel>()?
        .into_iter()
        .map(|cipher| cipher.into())
        .collect();

    attachments::hydrate_ciphers_attachments(&db, env.as_ref(), &mut restored_ciphers).await?;

    db::touch_user_updated_at(&db, &claims.sub).await?;

    Ok(Json(BulkRestoreResponse {
        data: restored_ciphers,
        object: "list".to_string(),
        continuation_token: None,
    }))
}

/// Handler for POST /api/ciphers
/// Accepts flat JSON structure (camelCase) as sent by Bitwarden clients
/// when creating a cipher without collection assignments.
#[worker::send]
pub async fn create_cipher_simple(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<CipherRequestData>,
) -> Result<Json<Cipher>, AppError> {
    let db = db::get_db(&env)?;
    let now = Utc::now();
    let now = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    let cipher_data = CipherData {
        name: payload.name,
        notes: payload.notes,
        type_fields: payload.type_fields,
    };

    let data_value = serde_json::to_value(&cipher_data).map_err(|_| AppError::Internal)?;

    let mut cipher = Cipher {
        id: Uuid::new_v4().to_string(),
        user_id: Some(claims.sub.clone()),
        organization_id: payload.organization_id.clone(),
        r#type: payload.r#type,
        data: data_value,
        favorite: payload.favorite.unwrap_or(false),
        folder_id: payload.folder_id.clone(),
        deleted_at: None,
        created_at: now.clone(),
        updated_at: now.clone(),
        object: "cipher".to_string(),
        organization_use_totp: false,
        edit: true,
        view_password: true,
        collection_ids: None,
        attachments: None,
    };

    let data = serde_json::to_string(&cipher.data).map_err(|_| AppError::Internal)?;

    query!(
        &db,
        "INSERT INTO ciphers (id, user_id, organization_id, type, data, favorite, folder_id, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
         cipher.id,
         cipher.user_id,
         cipher.organization_id,
         cipher.r#type,
         data,
         cipher.favorite,
         cipher.folder_id,
         cipher.created_at,
         cipher.updated_at,
    ).map_err(|_| AppError::Database)?
    .run()
    .await?;

    attachments::hydrate_cipher_attachments(&db, env.as_ref(), &mut cipher).await?;
    db::touch_user_updated_at(&db, &claims.sub).await?;

    Ok(Json(cipher))
}

/// Move selected ciphers to a folder (POST/PUT /api/ciphers/move)
#[worker::send]
pub async fn move_cipher_selected(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<MoveCipherData>,
) -> Result<Json<()>, AppError> {
    let db = db::get_db(&env)?;
    let user_id = &claims.sub;
    let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    // Validate folder exists and belongs to user (if folder_id is provided)
    if let Some(ref folder_id) = payload.folder_id {
        let folder_exists: Option<serde_json::Value> = db
            .prepare("SELECT id FROM folders WHERE id = ?1 AND user_id = ?2")
            .bind(&[folder_id.clone().into(), user_id.clone().into()])?
            .first(None)
            .await?;

        if folder_exists.is_none() {
            return Err(AppError::BadRequest(
                "Invalid folder: Folder does not exist or belongs to another user".to_string(),
            ));
        }
    }

    if payload.ids.is_empty() {
        return Ok(Json(()));
    }

    // Use json_each() to update all matching ciphers in a single query
    // This avoids N+1 query problem by updating all ciphers at once
    let ids_json = serde_json::to_string(&payload.ids).map_err(|_| AppError::Internal)?;

    // Update folder_id for all ciphers that belong to the user and are in the ids list
    // Using json_each() allows us to update all matching ciphers in a single query
    db.prepare(
        "UPDATE ciphers SET folder_id = ?1, updated_at = ?2 
         WHERE user_id = ?3 AND id IN (SELECT value FROM json_each(?4))",
    )
    .bind(&[
        payload
            .folder_id
            .clone()
            .map(|s| s.into())
            .unwrap_or(worker::wasm_bindgen::JsValue::NULL),
        now.into(),
        user_id.clone().into(),
        ids_json.into(),
    ])?
    .run()
    .await?;

    // Update user's revision date
    db::touch_user_updated_at(&db, user_id).await?;

    Ok(Json(()))
}

/// Purge the user's vault - delete all ciphers and folders
/// POST /api/ciphers/purge
///
/// This is a destructive operation that requires password verification.
/// In vaultwarden, this endpoint also supports purging organization vaults,
/// but this simplified version only supports personal vault purge.
#[worker::send]
pub async fn purge_vault(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<PasswordOrOtpData>,
) -> Result<Json<()>, AppError> {
    let db = db::get_db(&env)?;
    let user_id = &claims.sub;

    // Get the user from the database
    let user: Value = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[user_id.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;
    let user: User = serde_json::from_value(user).map_err(|_| AppError::Internal)?;

    // Validate password (OTP not supported in this simplified version)
    let provided_hash = payload
        .master_password_hash
        .ok_or_else(|| AppError::BadRequest("Missing master password hash".to_string()))?;

    let verification = user.verify_master_password(&provided_hash).await?;

    if !verification.is_valid() {
        return Err(AppError::Unauthorized("Invalid password".to_string()));
    }

    if attachments::attachments_enabled(env.as_ref()) {
        let bucket = attachments::require_bucket(env.as_ref())?;
        let keys = attachments::list_attachment_keys_for_user(&db, user_id).await?;
        attachments::delete_r2_objects(&bucket, &keys).await?;
    }

    // Delete all user's ciphers (both active and soft-deleted)
    query!(&db, "DELETE FROM ciphers WHERE user_id = ?1", user_id)
        .map_err(|_| AppError::Database)?
        .run()
        .await?;

    // Delete all user's folders
    query!(&db, "DELETE FROM folders WHERE user_id = ?1", user_id)
        .map_err(|_| AppError::Database)?
        .run()
        .await?;

    // Update user's revision date to trigger client sync
    db::touch_user_updated_at(&db, user_id).await?;

    Ok(Json(()))
}
