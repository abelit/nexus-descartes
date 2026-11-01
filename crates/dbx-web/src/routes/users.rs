//! Local user and role administration.
//!
//! Every handler checks `admin:users` itself. The server is the enforcement
//! point; hiding UI controls is only a convenience.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::Extension;
use axum::Json;
use dbx_core::audit::Actor;
use dbx_core::identity::{BuiltinRole, Permission};
use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::state::WebState;

#[derive(Serialize)]
pub struct UserView {
    pub id: String,
    pub email: String,
    pub display_name: String,
    pub status: String,
    pub is_builtin: bool,
    pub created_at: String,
    pub last_login_at: Option<String>,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
}

#[derive(Serialize)]
pub struct RoleView {
    pub code: String,
    pub name: String,
    pub description: String,
    pub permissions: Vec<String>,
}

fn require(actor: &Actor, permission: Permission) -> Result<(), AppError> {
    if dbx_core::identity::has_permission(&actor.roles, permission) {
        Ok(())
    } else {
        Err(AppError::forbidden(format!("PERMISSION_DENIED: {}", permission.as_str())))
    }
}

pub async fn list_roles(Extension(actor): Extension<Actor>) -> Result<Json<Vec<RoleView>>, AppError> {
    require(&actor, Permission::AdminUsers)?;
    Ok(Json(
        BuiltinRole::ALL
            .iter()
            .map(|role| RoleView {
                code: role.code().to_string(),
                name: role.name().to_string(),
                description: role.description().to_string(),
                permissions: role.permissions().iter().map(|permission| permission.as_str().to_string()).collect(),
            })
            .collect(),
    ))
}

pub async fn list_users(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
) -> Result<Json<Vec<UserView>>, AppError> {
    require(&actor, Permission::AdminUsers)?;
    let users = state.app.storage.list_users().await.map_err(AppError::from)?;
    let mut views = Vec::with_capacity(users.len());
    for user in users {
        let roles = state.app.storage.role_codes_for_user(user.id.clone()).await.unwrap_or_default();
        views.push(UserView {
            permissions: dbx_core::identity::permissions_for_roles(&roles),
            id: user.id,
            email: user.email,
            display_name: user.display_name,
            status: user.status,
            is_builtin: user.is_builtin,
            created_at: user.created_at,
            last_login_at: user.last_login_at,
            roles,
        });
    }
    Ok(Json(views))
}

#[derive(Deserialize)]
pub struct CreateUserRequest {
    pub email: String,
    pub display_name: String,
    pub password: String,
    #[serde(default = "default_role")]
    pub role: String,
}

fn default_role() -> String {
    "viewer".to_string()
}

pub async fn create_user(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Json(body): Json<CreateUserRequest>,
) -> Result<Json<UserView>, AppError> {
    require(&actor, Permission::AdminUsers)?;
    let email = body.email.trim().to_string();
    if email.is_empty() {
        return Err(AppError::bad_request("email is required"));
    }
    if body.password.chars().count() < 8 {
        return Err(AppError::bad_request("password must be at least 8 characters"));
    }
    let role =
        BuiltinRole::parse(&body.role).ok_or_else(|| AppError::bad_request(format!("Unknown role '{}'", body.role)))?;
    if state.app.storage.user_by_email(email.clone()).await.map_err(AppError::from)?.is_some() {
        return Err(AppError::conflict("email already exists"));
    }
    let password_hash = dbx_core::identity::hash_password(&body.password).map_err(|error| AppError::internal(error))?;
    let display_name =
        if body.display_name.trim().is_empty() { email.clone() } else { body.display_name.trim().to_string() };
    let user = state
        .app
        .storage
        .create_user(email, display_name, password_hash, role.code().to_string(), actor.id.clone())
        .await
        .map_err(AppError::from)?;
    let roles = state.app.storage.role_codes_for_user(user.id.clone()).await.unwrap_or_default();
    Ok(Json(UserView {
        permissions: dbx_core::identity::permissions_for_roles(&roles),
        id: user.id,
        email: user.email,
        display_name: user.display_name,
        status: user.status,
        is_builtin: user.is_builtin,
        created_at: user.created_at,
        last_login_at: user.last_login_at,
        roles,
    }))
}

#[derive(Deserialize)]
pub struct UpdateUserRequest {
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub role: Option<String>,
}

pub async fn update_user(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Path(user_id): Path<String>,
    Json(body): Json<UpdateUserRequest>,
) -> Result<Json<UserView>, AppError> {
    require(&actor, Permission::AdminUsers)?;
    let user = state
        .app
        .storage
        .user_by_id(user_id.clone())
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("user not found"))?;

    if let Some(status) = body.status.as_deref().map(str::trim) {
        if !matches!(status, "active" | "disabled") {
            return Err(AppError::bad_request("status must be active or disabled"));
        }
        if user.is_builtin && status == "disabled" {
            return Err(AppError::bad_request("the built-in administrator cannot be disabled"));
        }
        state.app.storage.set_user_status(user.id.clone(), status.to_string()).await.map_err(AppError::from)?;
        if status == "disabled" {
            state.app.storage.revoke_user_sessions(user.id.clone()).await.map_err(AppError::from)?;
        }
    }

    if let Some(role_code) = body.role.as_deref().map(str::trim).filter(|value| !value.is_empty()) {
        let role = BuiltinRole::parse(role_code)
            .ok_or_else(|| AppError::bad_request(format!("Unknown role '{role_code}'")))?;
        if user.is_builtin && role != BuiltinRole::Admin {
            return Err(AppError::bad_request("the built-in administrator must keep the admin role"));
        }
        for existing in state.app.storage.role_codes_for_user(user.id.clone()).await.unwrap_or_default() {
            state.app.storage.unbind_role(user.id.clone(), existing).await.map_err(AppError::from)?;
        }
        state
            .app
            .storage
            .bind_role(user.id.clone(), role.code().to_string(), actor.id.clone())
            .await
            .map_err(AppError::from)?;
        // Role changes take effect on the next request of that user: the
        // session's permissions are re-resolved from the database when the
        // session is loaded, so existing sessions are revoked to be safe.
        state.app.storage.revoke_user_sessions(user.id.clone()).await.map_err(AppError::from)?;
    }

    let refreshed = state
        .app
        .storage
        .user_by_id(user.id.clone())
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("user not found"))?;
    let roles = state.app.storage.role_codes_for_user(refreshed.id.clone()).await.unwrap_or_default();
    Ok(Json(UserView {
        permissions: dbx_core::identity::permissions_for_roles(&roles),
        id: refreshed.id,
        email: refreshed.email,
        display_name: refreshed.display_name,
        status: refreshed.status,
        is_builtin: refreshed.is_builtin,
        created_at: refreshed.created_at,
        last_login_at: refreshed.last_login_at,
        roles,
    }))
}

pub async fn revoke_user_sessions(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Path(user_id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    require(&actor, Permission::AdminUsers)?;
    state.drop_user_sessions(&user_id).await;
    let storage = state.app.storage.clone();
    storage.revoke_user_sessions(user_id.clone()).await.map_err(AppError::from)?;
    let now = chrono::Utc::now().timestamp_millis();
    let live = storage.live_web_sessions_for_user(user_id, now).await.map_err(AppError::from)?;
    for session in live {
        let _ = storage.revoke_web_session(session.id).await;
    }
    Ok(Json(serde_json::json!({ "ok": true })))
}
