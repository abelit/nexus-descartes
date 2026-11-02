//! Server-owned connection groups.
//!
//! These groups are the only authorization scope for connections: the client
//! sidebar layout is presentation only and is never trusted. Only users with
//! `admin:users` may change groups or membership.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::Extension;
use axum::Json;
use dbx_core::audit::Actor;
use dbx_core::identity::Permission;
use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::state::WebState;

fn require(actor: &Actor) -> Result<(), AppError> {
    if dbx_core::identity::has_permission(&actor.roles, Permission::AdminUsers) {
        Ok(())
    } else {
        Err(AppError::forbidden("PERMISSION_DENIED: admin:users"))
    }
}

#[derive(Debug, Serialize)]
pub struct GroupView {
    pub id: String,
    pub name: String,
    pub parent_id: Option<String>,
    pub connection_ids: Vec<String>,
}

pub async fn list_groups(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
) -> Result<Json<Vec<GroupView>>, AppError> {
    require(&actor)?;
    let groups = state.app.storage.list_connection_groups().await.map_err(AppError::from)?;
    Ok(Json(
        groups
            .into_iter()
            .map(|group| GroupView {
                id: group.id,
                name: group.name,
                parent_id: group.parent_id,
                connection_ids: group.connection_ids,
            })
            .collect(),
    ))
}

#[derive(Debug, Deserialize)]
pub struct CreateGroupRequest {
    pub name: String,
    #[serde(default)]
    pub parent_id: Option<String>,
}

pub async fn create_group(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Json(body): Json<CreateGroupRequest>,
) -> Result<Json<GroupView>, AppError> {
    require(&actor)?;
    let parent_id = body.parent_id.filter(|value| !value.trim().is_empty());
    let id =
        state.app.storage.create_connection_group(body.name.clone(), parent_id.clone(), Some(actor.id)).await.map_err(
            |error| match error.as_str() {
                "GROUP_PARENT_NOT_FOUND" => AppError::bad_request("parent group not found"),
                "GROUP_NAME_REQUIRED" => AppError::bad_request("name is required"),
                _ => AppError::from(error),
            },
        )?;
    Ok(Json(GroupView { id, name: body.name, parent_id, connection_ids: Vec::new() }))
}

#[derive(Debug, Deserialize)]
pub struct UpdateGroupRequest {
    pub name: String,
    #[serde(default)]
    pub parent_id: Option<String>,
}

pub async fn update_group(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Path(group_id): Path<String>,
    Json(body): Json<UpdateGroupRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    require(&actor)?;
    state
        .app
        .storage
        .update_connection_group(group_id.clone(), body.name, body.parent_id.filter(|value| !value.trim().is_empty()))
        .await
        .map_err(|error| match error.as_str() {
            "GROUP_CYCLE" => AppError::bad_request("a group cannot be nested under its own descendant"),
            "GROUP_NAME_REQUIRED" => AppError::bad_request("name is required"),
            _ => AppError::from(error),
        })?;
    Ok(Json(serde_json::json!({ "ok": true, "id": group_id })))
}

pub async fn delete_group(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Path(group_id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    require(&actor)?;
    state.app.storage.delete_connection_group(group_id.clone()).await.map_err(|error| match error.as_str() {
        "GROUP_HAS_CHILDREN" => AppError::conflict("group still has child groups"),
        "GROUP_IN_USE" => AppError::conflict("group is still referenced by a role binding"),
        _ => AppError::from(error),
    })?;
    Ok(Json(serde_json::json!({ "ok": true, "id": group_id })))
}

#[derive(Debug, Deserialize)]
pub struct SetMembersRequest {
    pub connection_ids: Vec<String>,
}

pub async fn set_members(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Path(group_id): Path<String>,
    Json(body): Json<SetMembersRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    require(&actor)?;
    state.app.storage.set_connection_group_members(group_id.clone(), body.connection_ids.clone()).await.map_err(
        |error| match error.as_str() {
            "GROUP_NOT_FOUND" => AppError::not_found("group not found"),
            _ => AppError::from(error),
        },
    )?;
    Ok(Json(serde_json::json!({ "ok": true, "id": group_id, "connection_ids": body.connection_ids })))
}
