use axum::{extract::State, Json};
use serde_json::Value;
use std::sync::Arc;
use worker::Env;

use crate::{
    auth::Claims,
    db,
    error::AppError,
    handlers::attachments,
    models::{
        cipher::{Cipher, CipherDBModel},
        folder::{Folder, FolderResponse},
        sync::{Profile, SyncResponse},
        user::User,
    },
};

#[worker::send]
pub async fn get_sync_data(
    claims: Claims,
    State(env): State<Arc<Env>>,
) -> Result<Json<SyncResponse>, AppError> {
    let user_id = claims.sub;
    let db = db::get_db(&env)?;

    // Fetch profile
    let user: User = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[user_id.clone().into()])?
        .first(None)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    // Fetch folders
    let folders_db: Vec<Folder> = db
        .prepare("SELECT * FROM folders WHERE user_id = ?1")
        .bind(&[user_id.clone().into()])?
        .all()
        .await?
        .results()?;

    let folders: Vec<FolderResponse> = folders_db.into_iter().map(|f| f.into()).collect();

    // Fetch ciphers
    let ciphers: Vec<Value> = db
        .prepare("SELECT * FROM ciphers WHERE user_id = ?1")
        .bind(&[user_id.clone().into()])?
        .all()
        .await?
        .results()?;

    let ciphers = ciphers
        .into_iter()
        .filter_map(
            |cipher| match serde_json::from_value::<CipherDBModel>(cipher.clone()) {
                Ok(cipher) => Some(cipher),
                Err(err) => {
                    log::warn!("Cannot parse {err:?} {cipher:?}");
                    None
                }
            },
        )
        .map(|cipher| cipher.into())
        .collect::<Vec<Cipher>>();

    let mut ciphers = ciphers;
    attachments::hydrate_ciphers_attachments(&db, env.as_ref(), &mut ciphers).await?;

    let profile = Profile::from_user(user)?;

    let response = SyncResponse {
        profile,
        folders,
        collections: Vec::new(),
        policies: Vec::new(),
        ciphers,
        domains: serde_json::Value::Null, // Ignored for basic implementation
        sends: Vec::new(),
        object: "sync".to_string(),
    };

    Ok(Json(response))
}
