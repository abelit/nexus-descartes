use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::header::USER_AGENT;
use axum::http::HeaderMap;
use axum::Extension;
use axum::Json;
use dbx_core::audit::Actor;
use dbx_core::history::{HistoryConnectionOption, HistoryEntry, HistorySearchRequest, HistorySearchResult};
use serde::Deserialize;

use crate::client_ip::ClientIp;
use crate::error::AppError;
use crate::state::WebState;

/// `None` for roles that may read every user's history; `Some(actor_id)` for
/// everyone else, who may only read (and never manage) their own entries.
fn history_view_scope(actor: &Actor) -> Option<String> {
    if dbx_core::identity::can_view_all_audit(&actor.roles) {
        None
    } else {
        Some(actor.id.clone())
    }
}

fn require_history_manager(actor: &Actor) -> Result<(), AppError> {
    if dbx_core::identity::has_permission(&actor.roles, dbx_core::identity::Permission::AdminSettings) {
        Ok(())
    } else {
        Err(AppError::forbidden("HISTORY_MANAGE_DENIED: only an administrator may delete or clear history"))
    }
}

#[derive(Deserialize)]
pub struct HistoryQuery {
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    pub activity_kind: Option<String>,
}

#[derive(Deserialize)]
pub struct HistoryClearQuery {
    pub source: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SaveHistoryRequest {
    pub entry: HistoryEntry,
}

pub async fn save_history(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    ClientIp(client_ip): ClientIp,
    headers: HeaderMap,
    Json(body): Json<SaveHistoryRequest>,
) -> Result<Json<()>, AppError> {
    let mut entry = body.entry;
    // A non-admin may not overwrite another user's row by reusing its id.
    if !dbx_core::identity::has_permission(&actor.roles, dbx_core::identity::Permission::AdminSettings) {
        let owner = state.app.storage.history_entry_actor_id(entry.id.clone()).await.map_err(AppError::from)?;
        if let Some(owner) = owner {
            if owner.as_deref() != Some(actor.id.as_str()) {
                return Err(AppError::forbidden("HISTORY_ENTRY_OWNED_BY_ANOTHER_USER"));
            }
        }
    }
    // Attribution is recorded by the server, never accepted from the client:
    // history is shared across users, so a forged actor would mislead readers.
    entry.actor_id = Some(actor.id);
    entry.actor_name = Some(actor.display_name).filter(|name| !name.trim().is_empty());
    entry.client_ip = Some(client_ip).filter(|ip| !ip.is_empty() && ip != "unknown");
    entry.user_agent = headers
        .get(USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.chars().take(512).collect())
        .filter(|value: &String| !value.is_empty());
    state.app.storage.save_history_entry(&entry).await.map_err(AppError::from)?;
    Ok(Json(()))
}

pub async fn load_history(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Query(q): Query<HistoryQuery>,
) -> Result<Json<Vec<HistoryEntry>>, AppError> {
    let limit = q.limit.unwrap_or(100);
    let offset = q.offset.unwrap_or(0);
    let entries = state
        .app
        .storage
        .load_history_entries(limit, offset, q.activity_kind, history_view_scope(&actor))
        .await
        .map_err(AppError::from)?;
    Ok(Json(entries))
}

pub async fn search_history(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Json(mut request): Json<HistorySearchRequest>,
) -> Result<Json<HistorySearchResult>, AppError> {
    // A scoped caller cannot ask for another actor's rows; a global reader may
    // use actor_id as a filter.
    if let Some(actor_id) = history_view_scope(&actor) {
        request.actor_id = Some(actor_id);
    }
    state.app.storage.search_history_entries(request).await.map(Json).map_err(AppError::from)
}

pub async fn load_history_connection_options(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
) -> Result<Json<Vec<HistoryConnectionOption>>, AppError> {
    state
        .app
        .storage
        .load_history_connection_options(history_view_scope(&actor))
        .await
        .map(Json)
        .map_err(AppError::from)
}

pub async fn clear_history(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Query(query): Query<HistoryClearQuery>,
) -> Result<Json<()>, AppError> {
    require_history_manager(&actor)?;
    if let Some(source) = query.source.as_deref().filter(|source| !source.trim().is_empty()) {
        state.app.storage.clear_history_by_source(source).await.map_err(AppError::from)?;
    } else {
        state.app.storage.clear_history().await.map_err(AppError::from)?;
    }
    Ok(Json(()))
}

pub async fn delete_history_entry(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Path(id): Path<String>,
) -> Result<Json<()>, AppError> {
    require_history_manager(&actor)?;
    state.app.storage.delete_history_entry(&id).await.map_err(AppError::from)?;
    Ok(Json(()))
}
