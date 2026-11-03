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

#[derive(Serialize, Debug, Clone)]
pub struct BindingView {
    pub role_code: String,
    pub scope_type: String,
    pub scope_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ScopeInput {
    #[serde(default = "global_scope")]
    pub scope_type: String,
    #[serde(default)]
    pub scope_id: Option<String>,
}

fn global_scope() -> String {
    "global".to_string()
}

async fn validate_scope(state: &WebState, scope: Option<&ScopeInput>) -> Result<(String, Option<String>), AppError> {
    let scope = scope.cloned().unwrap_or(ScopeInput { scope_type: global_scope(), scope_id: None });
    let scope_id = scope.scope_id.map(|value| value.trim().to_string()).filter(|value| !value.is_empty());
    match scope.scope_type.as_str() {
        "global" => {
            if scope_id.is_some() {
                return Err(AppError::bad_request("global scope must not specify scope_id"));
            }
            Ok(("global".to_string(), None))
        }
        "connection" => {
            let id = scope_id.ok_or_else(|| AppError::bad_request("connection scope requires scope_id"))?;
            let exists = state.app.configs.read().await.contains_key(&id);
            if !exists {
                return Err(AppError::bad_request("unknown connection in scope"));
            }
            Ok(("connection".to_string(), Some(id)))
        }
        "connection_group" => {
            let id = scope_id.ok_or_else(|| AppError::bad_request("connection_group scope requires scope_id"))?;
            let exists = state
                .app
                .storage
                .list_connection_groups()
                .await
                .map_err(AppError::from)?
                .iter()
                .any(|group| group.id == id);
            if !exists {
                return Err(AppError::bad_request("unknown connection group in scope"));
            }
            Ok(("connection_group".to_string(), Some(id)))
        }
        "database" | "schema" | "table" => {
            let id = scope_id.ok_or_else(|| AppError::bad_request("scope requires scope_id"))?;
            let parts: Vec<&str> = id.split("::").collect();
            let expected = match scope.scope_type.as_str() {
                "database" => 2,
                "schema" => 3,
                _ => 4,
            };
            if parts.len() != expected || parts.iter().any(|part| part.trim().is_empty()) {
                return Err(AppError::bad_request(format!(
                    "{} scope id must be '<connection_id>::<database>::<schema>::<table>' with {} part(s)",
                    scope.scope_type, expected
                )));
            }
            let exists = state.app.configs.read().await.contains_key(parts[0]);
            if !exists {
                return Err(AppError::bad_request("unknown connection in scope"));
            }
            Ok((scope.scope_type.clone(), Some(id)))
        }
        other => Err(AppError::bad_request(format!("Unknown scope type '{other}'"))),
    }
}

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
    pub bindings: Vec<BindingView>,
}

#[derive(Serialize)]
pub struct RoleView {
    pub code: String,
    pub name: String,
    pub description: String,
    pub permissions: Vec<String>,
    pub builtin: bool,
}

fn require(actor: &Actor, permission: Permission) -> Result<(), AppError> {
    if dbx_core::identity::has_permission(&actor.roles, permission) {
        Ok(())
    } else {
        Err(AppError::forbidden(format!("PERMISSION_DENIED: {}", permission.as_str())))
    }
}

pub async fn list_roles(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
) -> Result<Json<Vec<RoleView>>, AppError> {
    require(&actor, Permission::AdminUsers)?;
    let mut roles: Vec<RoleView> = BuiltinRole::ALL
        .iter()
        .map(|role| RoleView {
            code: role.code().to_string(),
            name: role.name().to_string(),
            description: role.description().to_string(),
            permissions: role.permissions().iter().map(|permission| permission.as_str().to_string()).collect(),
            builtin: true,
        })
        .collect();
    let custom = state.app.storage.list_custom_roles().await.map_err(AppError::from)?;
    for role in custom {
        roles.push(RoleView {
            code: role.code,
            name: role.name,
            description: role.description,
            permissions: role.permissions,
            builtin: false,
        });
    }
    Ok(Json(roles))
}

fn validate_permissions(permissions: &[String]) -> Result<Vec<String>, AppError> {
    let mut validated = Vec::with_capacity(permissions.len());
    for permission in permissions {
        let parsed = dbx_core::identity::Permission::parse(permission)
            .ok_or_else(|| AppError::bad_request(format!("Unknown permission '{permission}'")))?;
        validated.push(parsed.as_str().to_string());
    }
    validated.sort();
    validated.dedup();
    Ok(validated)
}

fn validate_role_code(code: &str) -> Result<(), AppError> {
    let valid = !code.is_empty()
        && code.len() <= 64
        && code
            .chars()
            .all(|character| character.is_ascii_lowercase() || character.is_ascii_digit() || "_.-".contains(character))
        && BuiltinRole::parse(code).is_none();
    if valid {
        Ok(())
    } else {
        Err(AppError::bad_request("Role code must be 1-64 chars of [a-z0-9_.-] and must not reuse a built-in code"))
    }
}

pub(crate) async fn reload_role_registry(state: &WebState) -> Result<(), AppError> {
    let roles = state.app.storage.list_custom_roles().await.map_err(AppError::from)?;
    dbx_core::identity::install_custom_roles(roles.into_iter().map(|role| (role.code, role.permissions)).collect());
    Ok(())
}

#[derive(Deserialize)]
pub struct CreateRoleRequest {
    pub code: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub permissions: Vec<String>,
}

pub async fn create_role(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Json(body): Json<CreateRoleRequest>,
) -> Result<Json<RoleView>, AppError> {
    require(&actor, Permission::AdminUsers)?;
    let code = body.code.trim().to_string();
    validate_role_code(&code)?;
    if body.name.trim().is_empty() {
        return Err(AppError::bad_request("name is required"));
    }
    let permissions = validate_permissions(&body.permissions)?;
    state
        .app
        .storage
        .create_custom_role(code.clone(), body.name.trim().to_string(), body.description.clone(), permissions.clone())
        .await
        .map_err(|error| match error.as_str() {
            "ROLE_CODE_TAKEN" => AppError::conflict("role code already exists"),
            _ => AppError::from(error),
        })?;
    reload_role_registry(&state).await?;
    Ok(Json(RoleView { code, name: body.name, description: body.description, permissions, builtin: false }))
}

#[derive(Deserialize)]
pub struct UpdateRoleRequest {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub permissions: Vec<String>,
}

pub async fn update_role(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Path(code): Path<String>,
    Json(body): Json<UpdateRoleRequest>,
) -> Result<Json<RoleView>, AppError> {
    require(&actor, Permission::AdminUsers)?;
    if body.name.trim().is_empty() {
        return Err(AppError::bad_request("name is required"));
    }
    let permissions = validate_permissions(&body.permissions)?;
    let affected_users = state.app.storage.user_ids_for_role(code.clone()).await.unwrap_or_default();
    state
        .app
        .storage
        .update_custom_role(code.clone(), body.name.trim().to_string(), body.description.clone(), permissions.clone())
        .await
        .map_err(|error| match error.as_str() {
            "ROLE_BUILTIN_IMMUTABLE" => AppError::forbidden("built-in roles cannot be edited"),
            "ROLE_NOT_FOUND" => AppError::not_found("role not found"),
            _ => AppError::from(error),
        })?;
    reload_role_registry(&state).await?;
    // Permissions changed: force affected users to sign in again.
    for user_id in affected_users {
        state.drop_user_sessions(&user_id).await;
        let _ = state.app.storage.revoke_user_sessions(user_id).await;
    }
    Ok(Json(RoleView { code, name: body.name, description: body.description, permissions, builtin: false }))
}

pub async fn delete_role(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Path(code): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    require(&actor, Permission::AdminUsers)?;
    state.app.storage.delete_custom_role(code.clone()).await.map_err(|error| match error.as_str() {
        "ROLE_BUILTIN_IMMUTABLE" => AppError::forbidden("built-in roles cannot be deleted"),
        "ROLE_NOT_FOUND" => AppError::not_found("role not found"),
        "ROLE_IN_USE" => AppError::conflict("role is still bound to users"),
        _ => AppError::from(error),
    })?;
    reload_role_registry(&state).await?;
    Ok(Json(serde_json::json!({ "ok": true })))
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
        let bindings = state
            .app
            .storage
            .bindings_for_user(user.id.clone())
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|binding| BindingView {
                role_code: binding.role_code,
                scope_type: binding.scope_type,
                scope_id: binding.scope_id,
            })
            .collect();
        views.push(UserView {
            permissions: dbx_core::identity::permissions_for_roles(&roles),
            bindings,
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
    #[serde(default)]
    pub scope: Option<ScopeInput>,
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
    if dbx_core::identity::role_permissions(&body.role).is_none() {
        return Err(AppError::bad_request(format!("Unknown role '{}'", body.role)));
    }
    let role_code = body.role.clone();
    if state.app.storage.user_by_email(email.clone()).await.map_err(AppError::from)?.is_some() {
        return Err(AppError::conflict("email already exists"));
    }
    let password_hash = dbx_core::identity::hash_password(&body.password).map_err(|error| AppError::internal(error))?;
    let display_name =
        if body.display_name.trim().is_empty() { email.clone() } else { body.display_name.trim().to_string() };
    let (scope_type, scope_id) = validate_scope(&state, body.scope.as_ref()).await?;
    let user = state
        .app
        .storage
        .create_user_scoped(
            email,
            display_name,
            password_hash,
            role_code.clone(),
            scope_type.clone(),
            scope_id.clone(),
            actor.id.clone(),
        )
        .await
        .map_err(AppError::from)?;
    let roles = state.app.storage.role_codes_for_user(user.id.clone()).await.unwrap_or_default();
    Ok(Json(UserView {
        permissions: dbx_core::identity::permissions_for_roles(&roles),
        bindings: vec![BindingView { role_code, scope_type, scope_id }],
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
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub scope: Option<ScopeInput>,
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

    if let Some(display_name) = body.display_name.as_deref().map(str::trim).filter(|value| !value.is_empty()) {
        state
            .app
            .storage
            .update_user_display_name(user.id.clone(), display_name.to_string())
            .await
            .map_err(AppError::from)?;
    }

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

    if body.role.is_some() || body.scope.is_some() {
        let existing_bindings = state.app.storage.bindings_for_user(user.id.clone()).await.unwrap_or_default();
        let role_code = body
            .role
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .or_else(|| existing_bindings.first().map(|binding| binding.role_code.clone()))
            .ok_or_else(|| AppError::bad_request("role is required"))?;
        if dbx_core::identity::role_permissions(&role_code).is_none() {
            return Err(AppError::bad_request(format!("Unknown role '{role_code}'")));
        }
        if user.is_builtin && role_code != "admin" {
            return Err(AppError::bad_request("the built-in administrator must keep the admin role"));
        }
        // Keep the existing scope unless a new one is supplied.
        let fallback_scope = existing_bindings
            .first()
            .map(|binding| ScopeInput { scope_type: binding.scope_type.clone(), scope_id: binding.scope_id.clone() });
        let (scope_type, scope_id) = validate_scope(&state, body.scope.as_ref().or(fallback_scope.as_ref())).await?;
        for existing in state.app.storage.role_codes_for_user(user.id.clone()).await.unwrap_or_default() {
            state.app.storage.unbind_role(user.id.clone(), existing).await.map_err(AppError::from)?;
        }
        // A scope change replaces the legacy single binding. Asset grants are
        // separate (possibly several); changing the legacy scope must not leave
        // them granting the old target.
        if body.scope.is_some() {
            state.app.storage.delete_asset_grants_for_user(user.id.clone()).await.map_err(AppError::from)?;
        }
        state
            .app
            .storage
            .bind_role_scoped(user.id.clone(), role_code, scope_type, scope_id, actor.id.clone())
            .await
            .map_err(AppError::from)?;
        // Binding changes take effect on the next request of that user: the
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
    let bindings = state
        .app
        .storage
        .bindings_for_user(refreshed.id.clone())
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|binding| BindingView {
            role_code: binding.role_code,
            scope_type: binding.scope_type,
            scope_id: binding.scope_id,
        })
        .collect();
    Ok(Json(UserView {
        permissions: dbx_core::identity::permissions_for_roles(&roles),
        bindings,
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

#[derive(Serialize)]
pub struct SessionView {
    pub id: String,
    pub created_at_ms: i64,
    pub last_seen_at_ms: i64,
    pub expires_at_ms: i64,
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
}

pub async fn list_user_sessions(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Path(user_id): Path<String>,
) -> Result<Json<Vec<SessionView>>, AppError> {
    require(&actor, Permission::AdminUsers)?;
    let now = chrono::Utc::now().timestamp_millis();
    let sessions = state.app.storage.live_web_sessions_for_user(user_id, now).await.map_err(AppError::from)?;
    Ok(Json(
        sessions
            .into_iter()
            .map(|session| SessionView {
                id: session.id,
                created_at_ms: session.created_at_ms,
                last_seen_at_ms: session.last_seen_at_ms,
                expires_at_ms: session.expires_at_ms,
                client_ip: session.client_ip,
                user_agent: session.user_agent,
            })
            .collect(),
    ))
}

pub async fn revoke_user_session(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Path((user_id, session_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, AppError> {
    require(&actor, Permission::AdminUsers)?;
    let now = chrono::Utc::now().timestamp_millis();
    let sessions = state.app.storage.live_web_sessions_for_user(user_id, now).await.map_err(AppError::from)?;
    if !sessions.iter().any(|session| session.id == session_id) {
        return Err(AppError::not_found("session not found for this user"));
    }
    state.revoke_session_by_db_id(&session_id).await;
    Ok(Json(serde_json::json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct ResetPasswordRequest {
    pub password: String,
}

pub async fn reset_user_password(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Path(user_id): Path<String>,
    Json(body): Json<ResetPasswordRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    require(&actor, Permission::AdminUsers)?;
    if body.password.chars().count() < 8 {
        return Err(AppError::bad_request("password must be at least 8 characters"));
    }
    let user = state
        .app
        .storage
        .user_by_id(user_id.clone())
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("user not found"))?;
    let hash = dbx_core::identity::hash_password(&body.password).map_err(AppError::internal)?;
    state.app.storage.update_user_password(user.id.clone(), hash.clone()).await.map_err(AppError::from)?;
    if user.is_builtin {
        // Keep the legacy mirror used by setup checks in sync.
        *state.password_hash.write().await = Some(hash);
    }
    state.drop_user_sessions(&user.id).await;
    state.app.storage.revoke_user_sessions(user.id).await.map_err(AppError::from)?;
    Ok(Json(serde_json::json!({ "ok": true })))
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

// ---------------------------------------------------------------------------
// Asset grants (connection / database / schema / table)
// ---------------------------------------------------------------------------

use dbx_core::audit::{AuditContext, AuditDecision, AuditEventInsert, AuditOperation, AuditOutcome, AuditSource};
use dbx_core::governance::assets::{AssetGrant, AssetTargetKind};

#[derive(Debug, Serialize)]
pub struct AssetGrantView {
    pub id: String,
    pub role_code: String,
    pub target_kind: String,
    pub connection_group_id: Option<String>,
    pub connection_id: Option<String>,
    pub database_name: Option<String>,
    pub schema_name: Option<String>,
    pub table_name: Option<String>,
    pub name_pattern: bool,
    pub expires_at: Option<String>,
    pub granted_by: Option<String>,
    pub reason: String,
    pub created_at: String,
}

impl From<AssetGrant> for AssetGrantView {
    fn from(grant: AssetGrant) -> Self {
        Self {
            id: grant.id,
            role_code: grant.role_code,
            target_kind: grant.target_kind.as_str().to_string(),
            connection_group_id: grant.connection_group_id,
            connection_id: grant.connection_id,
            database_name: grant.database_name,
            schema_name: grant.schema_name,
            table_name: grant.table_name,
            name_pattern: grant.name_pattern,
            expires_at: grant.expires_at,
            granted_by: grant.granted_by,
            reason: grant.reason,
            created_at: grant.created_at,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateGrantRequest {
    pub role_code: String,
    pub target_kind: String,
    #[serde(default)]
    pub connection_group_id: Option<String>,
    #[serde(default)]
    pub connection_id: Option<String>,
    #[serde(default)]
    pub database_name: Option<String>,
    #[serde(default)]
    pub schema_name: Option<String>,
    #[serde(default)]
    pub table_name: Option<String>,
    #[serde(default)]
    pub name_pattern: bool,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub reason: String,
}

fn clean(value: Option<String>) -> Option<String> {
    value.map(|value| value.trim().to_string()).filter(|value| !value.is_empty())
}

async fn validate_grant(
    state: &WebState,
    user_id: &str,
    actor: &Actor,
    body: CreateGrantRequest,
) -> Result<AssetGrant, AppError> {
    let target_kind = AssetTargetKind::parse(&body.target_kind).ok_or_else(|| {
        AppError::bad_request("target_kind must be connection_group, connection, database, schema, or table")
    })?;
    if dbx_core::identity::role_permissions(&body.role_code).is_none() {
        return Err(AppError::bad_request(format!("Unknown role '{}'", body.role_code)));
    }
    let connection_group_id = clean(body.connection_group_id);
    let connection_id = clean(body.connection_id);
    let database_name = clean(body.database_name);
    let schema_name = clean(body.schema_name);
    let table_name = clean(body.table_name);
    let only = |allowed: bool, label: &str| -> Result<(), AppError> {
        if allowed {
            Ok(())
        } else {
            Err(AppError::bad_request(format!("{label} is not valid for this target_kind")))
        }
    };
    match target_kind {
        AssetTargetKind::ConnectionGroup => {
            let group =
                connection_group_id.as_ref().ok_or_else(|| AppError::bad_request("connection_group_id is required"))?;
            let exists = state
                .app
                .storage
                .list_connection_groups()
                .await
                .map_err(AppError::from)?
                .iter()
                .any(|g| &g.id == group);
            if !exists {
                return Err(AppError::bad_request("unknown connection group"));
            }
            only(
                connection_id.is_none() && database_name.is_none() && schema_name.is_none() && table_name.is_none(),
                "connection/database",
            )?;
        }
        AssetTargetKind::Connection => {
            let connection =
                connection_id.as_ref().ok_or_else(|| AppError::bad_request("connection_id is required"))?;
            if !state.app.configs.read().await.contains_key(connection) {
                return Err(AppError::bad_request("unknown connection"));
            }
            only(
                connection_group_id.is_none()
                    && database_name.is_none()
                    && schema_name.is_none()
                    && table_name.is_none(),
                "group/database",
            )?;
        }
        AssetTargetKind::Database | AssetTargetKind::Schema | AssetTargetKind::Table => {
            let connection =
                connection_id.as_ref().ok_or_else(|| AppError::bad_request("connection_id is required"))?;
            let is_mongo = {
                let configs = state.app.configs.read().await;
                match configs.get(connection) {
                    Some(config) => config.db_type == dbx_core::models::connection::DatabaseType::MongoDb,
                    None => return Err(AppError::bad_request("unknown connection")),
                }
            };
            let database = database_name.as_ref().ok_or_else(|| AppError::bad_request("database_name is required"))?;
            if database.is_empty() {
                return Err(AppError::bad_request("database_name is required"));
            }
            only(connection_group_id.is_none(), "connection_group_id")?;
            if is_mongo && target_kind == AssetTargetKind::Schema {
                return Err(AppError::bad_request(
                    "MongoDB connections have no schema level; grant a collection instead",
                ));
            }
            if target_kind == AssetTargetKind::Schema || target_kind == AssetTargetKind::Table {
                // MongoDB collections are addressed by database + collection:
                // there is no schema level to store.
                if schema_name.is_none() && !is_mongo {
                    return Err(AppError::bad_request("schema_name is required"));
                }
            } else {
                only(schema_name.is_none() && table_name.is_none(), "schema/table")?;
            }
            if target_kind == AssetTargetKind::Table {
                if table_name.is_none() {
                    return Err(AppError::bad_request("table_name is required"));
                }
            } else {
                only(table_name.is_none(), "table_name")?;
            }
        }
    }
    if body.name_pattern && target_kind != AssetTargetKind::Table {
        return Err(AppError::bad_request("name_pattern is only supported for table grants"));
    }
    if let Some(expires) = body.expires_at.as_deref() {
        let parsed = chrono::DateTime::parse_from_rfc3339(expires)
            .map_err(|_| AppError::bad_request("expires_at must be an RFC3339 timestamp"))?;
        if parsed.timestamp_millis() <= chrono::Utc::now().timestamp_millis() {
            return Err(AppError::bad_request("expires_at must be in the future"));
        }
    }
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    Ok(AssetGrant {
        id: uuid::Uuid::new_v4().to_string(),
        principal_type: "user".to_string(),
        principal_id: user_id.to_string(),
        role_code: body.role_code,
        target_kind,
        connection_group_id,
        connection_id,
        database_name,
        schema_name,
        table_name,
        name_pattern: body.name_pattern,
        expires_at: clean(body.expires_at),
        granted_by: Some(actor.id.clone()),
        reason: body.reason,
        created_at: now.clone(),
        updated_at: now,
    })
}

fn record_grant_audit(state: &WebState, actor: &Actor, action: &str, grant: &AssetGrant) {
    let context = dbx_core::audit::current_audit_context().unwrap_or_else(|| AuditContext {
        actor: actor.clone(),
        source: AuditSource::Web,
        client_ip: None,
        user_agent: None,
        request_id: None,
        execution_id: None,
    });
    let mut event =
        AuditEventInsert::new(&context, AuditOperation::Admin, AuditDecision::Allowed, AuditOutcome::Success);
    event.resource_type = Some("asset_grant".to_string());
    event.resource_id = Some(grant.id.clone());
    event.details_json = Some(
        serde_json::json!({
            "action": action,
            "principal_id": grant.principal_id,
            "role_code": grant.role_code,
            "target_kind": grant.target_kind.as_str(),
            "connection_id": grant.connection_id,
            "database_name": grant.database_name,
            "schema_name": grant.schema_name,
            "table_name": grant.table_name,
        })
        .to_string(),
    );
    state.app.record_audit(event);
}

pub async fn list_bindings(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Path(user_id): Path<String>,
) -> Result<Json<Vec<AssetGrantView>>, AppError> {
    require(&actor, Permission::AdminUsers)?;
    let grants = state.app.storage.asset_grants_for_user(user_id).await.map_err(AppError::from)?;
    Ok(Json(grants.into_iter().map(AssetGrantView::from).collect()))
}

pub async fn create_binding(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Path(user_id): Path<String>,
    Json(body): Json<CreateGrantRequest>,
) -> Result<Json<AssetGrantView>, AppError> {
    require(&actor, Permission::AdminUsers)?;
    state
        .app
        .storage
        .user_by_id(user_id.clone())
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("user not found"))?;
    let grant = validate_grant(&state, &user_id, &actor, body).await?;
    state.app.storage.create_asset_grant(grant.clone()).await.map_err(AppError::from)?;
    state.app.storage.revoke_user_sessions(user_id).await.map_err(AppError::from)?;
    state.drop_user_sessions(&grant.principal_id).await;
    record_grant_audit(&state, &actor, "created", &grant);
    Ok(Json(AssetGrantView::from(grant)))
}

pub async fn delete_binding(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Path((user_id, binding_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, AppError> {
    require(&actor, Permission::AdminUsers)?;
    let grant = state
        .app
        .storage
        .asset_grant_by_id(binding_id.clone())
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("binding not found"))?;
    if grant.principal_id != user_id {
        return Err(AppError::not_found("binding not found"));
    }
    if !state.app.storage.delete_asset_grant(binding_id, user_id.clone()).await.map_err(AppError::from)? {
        return Err(AppError::not_found("binding not found"));
    }
    state.app.storage.revoke_user_sessions(user_id).await.map_err(AppError::from)?;
    state.drop_user_sessions(&grant.principal_id).await;
    record_grant_audit(&state, &actor, "deleted", &grant);
    Ok(Json(serde_json::json!({ "ok": true })))
}
