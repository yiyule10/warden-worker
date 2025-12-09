use std::sync::Arc;

use axum::{extract::DefaultBodyLimit, Extension};
use tower_http::cors::{Any, CorsLayer};
use tower_service::Service;
use worker::*;

mod auth;
mod crypto;
mod db;
mod error;
mod handlers;
mod models;
mod router;

/// Base URL extracted from the incoming request, used for config endpoint.
#[derive(Clone)]
pub struct BaseUrl(pub String);

#[event(fetch)]
pub async fn main(
    req: HttpRequest,
    env: Env,
    _ctx: Context,
) -> Result<axum::http::Response<axum::body::Body>> {
    // Set up logging
    console_error_panic_hook::set_once();
    let _ = console_log::init_with_level(log::Level::Debug);

    // Extract base URL from the incoming request
    let uri = req.uri().clone();
    let base_url = format!(
        "{}://{}",
        uri.scheme_str().unwrap_or("https"),
        uri.authority().map(|a| a.as_str()).unwrap_or("localhost")
    );

    let env = Arc::new(env);

    // Allow all origins for CORS, which is typical for a public API like Bitwarden's.
    let cors = CorsLayer::new()
        .allow_methods(Any)
        .allow_headers(Any)
        .allow_origin(Any);

    // Attachment uploads/downloads are handled in entry.js for zero-copy streaming,
    // so we can use a conservative body limit here (5MB) for regular API requests.
    const BODY_LIMIT: usize = 5 * 1024 * 1024;

    let mut app = router::api_router((*env).clone())
        .layer(Extension(BaseUrl(base_url)))
        .layer(cors)
        .layer(DefaultBodyLimit::max(BODY_LIMIT));

    Ok(app.call(req).await?)
}

/// Scheduled event handler for cron-triggered tasks.
///
/// This handler is triggered by Cloudflare's cron triggers configured in wrangler.toml.
/// It performs automatic cleanup of soft-deleted ciphers that have exceeded the
/// retention period (default: 30 days, configurable via TRASH_AUTO_DELETE_DAYS env var).
#[event(scheduled)]
pub async fn scheduled(_event: ScheduledEvent, env: Env, _ctx: ScheduleContext) {
    // Set up logging
    console_error_panic_hook::set_once();
    let _ = console_log::init_with_level(log::Level::Debug);

    log::info!("Scheduled task triggered: purging soft-deleted ciphers");

    match handlers::purge::purge_deleted_ciphers(&env).await {
        Ok(count) => {
            log::info!("Scheduled purge completed: {} cipher(s) removed", count);
        }
        Err(e) => {
            log::error!("Scheduled purge failed: {:?}", e);
        }
    }
}
