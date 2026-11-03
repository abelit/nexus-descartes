use std::sync::Arc;

use axum::extract::{Query, State};
use axum::{Extension, Json};
use dbx_core::audit::Actor;
use serde::Deserialize;

use crate::error::AppError;
use crate::state::WebState;

/// Object metadata cache keys are `object-ddl:v1:<connection>:<database>:<schema>:<table>:...`
/// and `object-meta:v1:...`. Returns the object tuple when the key has that
/// shape; cache segments are URI-encoded, and only plain identifiers are
/// resolved here (anything else fails closed for managed users).
fn object_cache_target(key: &str) -> Option<(&str, &str, &str, &str)> {
    let parts: Vec<&str> = key.split(':').collect();
    if !matches!(parts.first().copied(), Some("object-ddl" | "object-meta")) || parts.len() < 6 {
        return None;
    }
    Some((parts[2], parts[3], parts[4], parts[5]))
}

async fn authorize_cache_key(state: &WebState, actor: &Actor, key: &str) -> Result<(), AppError> {
    if !dbx_core::governance::assets::actor_is_managed(actor) {
        return Ok(());
    }
    let Some((connection_id, database, schema, table)) = object_cache_target(key) else {
        return Err(AppError::forbidden(
            "ASSET_ACCESS_DENIED: this schema-cache key cannot be mapped to an authorized object",
        ));
    };
    let snapshot =
        dbx_core::governance::assets::load_asset_snapshot(&state.app, &actor.id).await.map_err(AppError::from)?;
    if !snapshot.authorizes_table(connection_id, database, schema, table) {
        return Err(AppError::forbidden("ASSET_ACCESS_DENIED: the cached object is outside the user's asset grants"));
    }
    Ok(())
}

#[derive(Deserialize)]
pub struct SchemaCacheKeyQuery {
    pub cache_key: String,
}

#[derive(Deserialize)]
pub struct SchemaCachePrefixQuery {
    pub prefix: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SaveSchemaCacheRequest {
    pub cache_key: String,
    pub payload: serde_json::Value,
}

pub async fn save_schema_cache(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Json(body): Json<SaveSchemaCacheRequest>,
) -> Result<Json<()>, AppError> {
    authorize_cache_key(&state, &actor, &body.cache_key).await?;
    state.app.storage.save_schema_cache(&body.cache_key, &body.payload).await.map_err(AppError::from)?;
    Ok(Json(()))
}

pub async fn load_schema_cache(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Query(query): Query<SchemaCacheKeyQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    authorize_cache_key(&state, &actor, &query.cache_key).await?;
    let payload = state.app.storage.load_schema_cache(&query.cache_key).await.map_err(AppError::from)?;
    Ok(Json(payload.unwrap_or(serde_json::json!(null))))
}

pub async fn delete_schema_cache_prefix(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Query(query): Query<SchemaCachePrefixQuery>,
) -> Result<Json<()>, AppError> {
    if dbx_core::governance::assets::actor_is_managed(&actor) {
        let connection_id = query.prefix.split(':').nth(2).unwrap_or("");
        let snapshot =
            dbx_core::governance::assets::load_asset_snapshot(&state.app, &actor.id).await.map_err(AppError::from)?;
        if connection_id.is_empty() || !snapshot.can_navigate_connection(connection_id) {
            return Err(AppError::forbidden(
                "ASSET_ACCESS_DENIED: the cache prefix is outside the user's asset grants",
            ));
        }
    }
    state.app.storage.delete_schema_cache_prefix(&query.prefix).await.map_err(AppError::from)?;
    Ok(Json(()))
}
