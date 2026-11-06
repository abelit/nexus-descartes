//! Local user and role administration.
//!
//! Every handler checks `admin:users` itself. The server is the enforcement
//! point; hiding UI controls is only a convenience.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::Extension;
use axum::Json;
use dbx_core::audit::Actor;
use dbx_core::governance::assets::{
    grant_from_scope, load_asset_snapshot, AccessRequest, AccessRequestStatus, AssetGrant, AssetScopeSnapshot,
    AssetTargetKind,
};
use dbx_core::identity::{has_permission, permissions_for_roles, role_permissions, BuiltinRole, Permission};
use serde::{Deserialize, Deserializer, Serialize};

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
    /// Roles held only through asset grants.
    pub asset_roles: Vec<String>,
    pub permissions: Vec<String>,
    /// Global and asset-scoped permissions together; used by the UI to explain
    /// why a lower-privileged administrator cannot reset this account.
    pub effective_permissions: Vec<String>,
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

fn role_permission_codes(role_code: &str) -> Result<Vec<String>, AppError> {
    role_permissions(role_code).ok_or_else(|| AppError::bad_request(format!("Unknown role '{role_code}'")))
}

/// Permissions the actor must already hold before it can hand them out.
/// `admin:users` alone is not enough to create a privilege it does not have.
fn missing_global_permissions(actor: &Actor, required: &[String]) -> Vec<String> {
    required
        .iter()
        .filter(|code| !Permission::parse(code).is_some_and(|permission| has_permission(&actor.roles, permission)))
        .cloned()
        .collect()
}

fn ensure_can_assign_permissions(actor: &Actor, permissions: &[String]) -> Result<(), AppError> {
    let missing = missing_global_permissions(actor, permissions);
    if missing.is_empty() {
        Ok(())
    } else {
        Err(AppError::forbidden(format!(
            "GRANT_CEILING: cannot assign permissions the current user does not hold: {}",
            missing.join(", ")
        )))
    }
}

fn ensure_can_assign_global_role(actor: &Actor, role_code: &str) -> Result<(), AppError> {
    let required = role_permission_codes(role_code)?;
    ensure_can_assign_permissions(actor, &required)
        .map_err(|_| AppError::forbidden(format!("GRANT_CEILING: cannot assign role '{role_code}'")))
}

/// A user can only be administered by someone who already holds every
/// permission that user can exercise, including permissions obtained through
/// asset grants. This stops password resets and privileged status changes from
/// becoming an impersonation or lockout path into a more privileged account.
async fn ensure_can_manage_target(state: &WebState, actor: &Actor, user_id: &str) -> Result<(), AppError> {
    if actor.id == user_id {
        // Editing oneself cannot add permissions beyond the ceiling, which is
        // checked separately for new role assignments.
        return Ok(());
    }
    let mut roles = state.app.storage.role_codes_for_user(user_id.to_string()).await.map_err(AppError::from)?;
    roles.extend(state.app.storage.asset_role_codes_for_user(user_id.to_string()).await.map_err(AppError::from)?);
    roles.sort();
    roles.dedup();
    let required = permissions_for_roles(&roles);
    let missing = missing_global_permissions(actor, &required);
    if missing.is_empty() {
        Ok(())
    } else {
        Err(AppError::forbidden(format!(
            "USER_MANAGEMENT_CEILING: the target user holds permissions the current user does not: {}",
            missing.join(", ")
        )))
    }
}

fn asset_permissions_for_role(role_code: &str) -> Result<Vec<Permission>, AppError> {
    Ok(role_permission_codes(role_code)?
        .iter()
        .filter_map(|code| Permission::parse(code))
        // Approval-only roles cannot reach an asset: approval visibility is
        // anchored on `connection:read`, so such a grant would be a no-op.
        .filter(|permission| {
            matches!(
                permission,
                Permission::ConnectionRead
                    | Permission::QueryRead
                    | Permission::QueryWrite
                    | Permission::QueryDdl
                    | Permission::ExportData
                    | Permission::ImportData
                    | Permission::UnmaskData
                    | Permission::RowFilterBypass
            )
        })
        .collect())
}

/// Whether two grants protect the same natural target for the same role.
fn same_grant_target(left: &AssetGrant, right: &AssetGrant) -> bool {
    left.role_code == right.role_code
        && left.target_kind == right.target_kind
        && left.connection_group_id == right.connection_group_id
        && left.connection_id == right.connection_id
        && left.database_name == right.database_name
        && left.schema_name == right.schema_name
        && left.table_name == right.table_name
        && left.name_pattern == right.name_pattern
}

/// A self-service request may only name a data role: every permission the role
/// carries must be satisfiable inside an asset target. Administrator and DBA
/// also carry global-only permissions, so they cannot be requested; an
/// administrator who needs that scope grants it directly.
fn is_requestable_role(role_code: &str) -> Result<bool, AppError> {
    let codes = role_permission_codes(role_code)?;
    let all_asset_scopeable =
        codes.iter().all(|code| Permission::parse(code).is_some_and(|permission| permission.is_asset_scopeable()));
    Ok(all_asset_scopeable && !asset_permissions_for_role(role_code)?.is_empty())
}

fn role_grants_permission(role_code: &str, permission: Permission) -> bool {
    has_permission(&[role_code.to_string()], permission)
}

/// Whether the actor's own grants cover the exact target a new grant would
/// give away. A connection grant must be covered broadly; a table grant only
/// needs to cover that table.
fn actor_covers_grant(snapshot: &AssetScopeSnapshot, grant: &AssetGrant, permission: Permission) -> bool {
    match grant.target_kind {
        AssetTargetKind::ConnectionGroup => {
            let Some(group) = grant.connection_group_id.as_deref() else {
                return false;
            };
            match snapshot.group_connections.get(group) {
                Some(connections) if !connections.is_empty() => connections.iter().all(|connection| {
                    snapshot.permits(connection, None, None, None, permission.as_str(), false).is_some()
                }),
                // An empty group protects no asset; require a direct grant on
                // the same group or a global permission.
                _ => {
                    snapshot.has_global_permission(permission.as_str())
                        || snapshot.grants.iter().any(|own| {
                            own.target_kind == AssetTargetKind::ConnectionGroup
                                && own.connection_group_id.as_deref() == Some(group)
                                && role_grants_permission(&own.role_code, permission)
                        })
                }
            }
        }
        AssetTargetKind::Connection => grant.connection_id.as_deref().is_some_and(|connection| {
            snapshot.permits(connection, None, None, None, permission.as_str(), false).is_some()
        }),
        AssetTargetKind::Database => grant.connection_id.as_deref().is_some_and(|connection| {
            snapshot
                .permits(connection, grant.database_name.as_deref(), None, None, permission.as_str(), false)
                .is_some()
        }),
        AssetTargetKind::Schema => grant.connection_id.as_deref().is_some_and(|connection| {
            snapshot
                .permits(
                    connection,
                    grant.database_name.as_deref(),
                    grant.schema_name.as_deref(),
                    None,
                    permission.as_str(),
                    false,
                )
                .is_some()
        }),
        AssetTargetKind::Table => grant.connection_id.as_deref().is_some_and(|connection| {
            snapshot
                .permits(
                    connection,
                    grant.database_name.as_deref(),
                    grant.schema_name.as_deref(),
                    grant.table_name.as_deref(),
                    permission.as_str(),
                    false,
                )
                .is_some()
        }),
    }
}

async fn ensure_can_grant_asset(state: &WebState, actor: &Actor, grant: &AssetGrant) -> Result<(), AppError> {
    let required = asset_permissions_for_role(&grant.role_code)?;
    if required.is_empty() {
        return Err(AppError::bad_request(format!(
            "ROLE_HAS_NO_ASSET_PERMISSIONS: role '{}' cannot be used for an asset grant",
            grant.role_code
        )));
    }
    let snapshot = load_asset_snapshot(&state.app, &actor.id).await.map_err(AppError::from)?;
    let missing: Vec<String> = required
        .iter()
        .filter(|permission| !actor_covers_grant(&snapshot, grant, **permission))
        .map(|permission| permission.as_str().to_string())
        .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(AppError::forbidden(format!(
            "GRANT_CEILING: cannot grant role '{}' at this scope because the current user lacks: {}",
            grant.role_code,
            missing.join(", ")
        )))
    }
}

pub async fn list_roles(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
) -> Result<Json<Vec<RoleView>>, AppError> {
    build_role_views(&state, &actor).await.map(Json)
}

/// Shared by the HTTP handler and the AI governance tools.
pub(crate) async fn build_role_views(state: &WebState, actor: &Actor) -> Result<Vec<RoleView>, AppError> {
    require(actor, Permission::AdminUsers)?;
    let overrides = state.app.storage.list_builtin_role_overrides().await.map_err(AppError::from)?;
    let mut roles: Vec<RoleView> = BuiltinRole::ALL
        .iter()
        .map(|role| {
            let overridden = overrides.iter().find(|entry| entry.code == role.code());
            RoleView {
                code: role.code().to_string(),
                name: overridden.map(|entry| entry.name.clone()).unwrap_or_else(|| role.name().to_string()),
                description: overridden
                    .map(|entry| entry.description.clone())
                    .unwrap_or_else(|| role.description().to_string()),
                permissions: overridden.map(|entry| entry.permissions.clone()).unwrap_or_else(|| {
                    role.permissions().iter().map(|permission| permission.as_str().to_string()).collect()
                }),
                builtin: true,
            }
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
    Ok(roles)
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
    let overrides = state.app.storage.list_builtin_role_overrides().await.map_err(AppError::from)?;
    dbx_core::identity::install_role_registry(
        roles.into_iter().map(|role| (role.code, role.permissions)).collect(),
        overrides.into_iter().map(|role| (role.code, role.permissions)).collect(),
    );
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
    ensure_can_assign_permissions(&actor, &permissions)?;
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
    ensure_can_assign_permissions(&actor, &permissions)?;
    let affected_users = state.app.storage.user_ids_for_role(code.clone()).await.unwrap_or_default();
    if let Some(builtin) = BuiltinRole::parse(&code) {
        // The administrator role stays immutable so a deployment cannot lock
        // itself out of every admin capability.
        if builtin == BuiltinRole::Admin {
            return Err(AppError::forbidden("ADMIN_ROLE_IMMUTABLE: the administrator role cannot be edited"));
        }
        if permissions.is_empty() {
            return Err(AppError::bad_request("a built-in role must keep at least one permission"));
        }
        state
            .app
            .storage
            .upsert_builtin_role_override(
                code.clone(),
                body.name.trim().to_string(),
                body.description.clone(),
                permissions.clone(),
            )
            .await
            .map_err(AppError::from)?;
        reload_role_registry(&state).await?;
        for user_id in affected_users {
            state.drop_user_sessions(&user_id).await;
            let _ = state.app.storage.revoke_user_sessions(user_id).await;
        }
        return Ok(Json(RoleView { code, name: body.name, description: body.description, permissions, builtin: true }));
    }
    state
        .app
        .storage
        .update_custom_role(code.clone(), body.name.trim().to_string(), body.description.clone(), permissions.clone())
        .await
        .map_err(|error| match error.as_str() {
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
    if let Some(builtin) = BuiltinRole::parse(&code) {
        if builtin == BuiltinRole::Admin {
            return Err(AppError::forbidden("ADMIN_ROLE_IMMUTABLE: the administrator role cannot be reset"));
        }
        state.app.storage.delete_builtin_role_override(code).await.map_err(AppError::from)?;
        reload_role_registry(&state).await?;
        return Ok(Json(serde_json::json!({ "ok": true })));
    }
    state.app.storage.delete_custom_role(code.clone()).await.map_err(|error| match error.as_str() {
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
    build_user_views(&state, &actor).await.map(Json)
}

/// Shared by the HTTP handler and the AI governance tools.
pub(crate) async fn build_user_views(state: &WebState, actor: &Actor) -> Result<Vec<UserView>, AppError> {
    require(actor, Permission::AdminUsers)?;
    let users = state.app.storage.list_users().await.map_err(AppError::from)?;
    let mut views = Vec::with_capacity(users.len());
    for user in users {
        let roles = state.app.storage.role_codes_for_user(user.id.clone()).await.unwrap_or_default();
        let asset_roles = state.app.storage.asset_role_codes_for_user(user.id.clone()).await.unwrap_or_default();
        let mut effective_roles = roles.clone();
        effective_roles.extend(asset_roles.clone());
        let effective_permissions = dbx_core::identity::permissions_for_roles(&effective_roles);
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
            effective_permissions,
            asset_roles,
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
    Ok(views)
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
    role_permission_codes(&body.role)?;
    let role_code = body.role.clone();
    if state.app.storage.user_by_email(email.clone()).await.map_err(AppError::from)?.is_some() {
        return Err(AppError::conflict("email already exists"));
    }
    let (scope_type, scope_id) = validate_scope(&state, body.scope.as_ref()).await?;
    if scope_type == "global" {
        ensure_can_assign_global_role(&actor, &role_code)?;
    } else {
        let grant = grant_from_scope("", &role_code, &scope_type, scope_id.as_deref(), Some(&actor.id))
            .ok_or_else(|| AppError::bad_request("invalid scope"))?;
        ensure_can_grant_asset(&state, &actor, &grant).await?;
    }
    let password_hash = dbx_core::identity::hash_password(&body.password).map_err(|error| AppError::internal(error))?;
    let display_name =
        if body.display_name.trim().is_empty() { email.clone() } else { body.display_name.trim().to_string() };
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
    let asset_roles = state.app.storage.asset_role_codes_for_user(user.id.clone()).await.unwrap_or_default();
    let mut effective_roles = roles.clone();
    effective_roles.extend(asset_roles.clone());
    let permissions = dbx_core::identity::permissions_for_roles(&roles);
    Ok(Json(UserView {
        effective_permissions: dbx_core::identity::permissions_for_roles(&effective_roles),
        permissions,
        asset_roles,
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
    /// Remove every global role while keeping asset grants. Used to downgrade
    /// an account to asset-only access.
    #[serde(default)]
    pub clear_global_role: Option<bool>,
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

    if body.status.is_some() {
        // Disabling a user is not impersonation, but it must not let a
        // lower-privileged administrator disable an administrator.
        let target_roles = state.app.storage.role_codes_for_user(user.id.clone()).await.unwrap_or_default();
        let target_permissions = permissions_for_roles(&target_roles);
        if target_permissions.iter().any(|permission| permission.starts_with("admin:")) {
            ensure_can_manage_target(&state, &actor, &user.id).await?;
        }
    }

    if let Some(status) = body.status.as_deref().map(str::trim) {
        if !matches!(status, "active" | "disabled") {
            return Err(AppError::bad_request("status must be active or disabled"));
        }
        if user.is_builtin && status == "disabled" {
            return Err(AppError::bad_request("the built-in administrator cannot be disabled"));
        }
        if actor.id == user.id && status == "disabled" {
            return Err(AppError::bad_request("you cannot disable your own account"));
        }
        state.app.storage.set_user_status(user.id.clone(), status.to_string()).await.map_err(AppError::from)?;
        if status == "disabled" {
            state.app.storage.revoke_user_sessions(user.id.clone()).await.map_err(AppError::from)?;
        }
    }

    if body.clear_global_role.unwrap_or(false) {
        if body.role.is_some() || body.scope.is_some() {
            return Err(AppError::bad_request("clear_global_role cannot be combined with role or scope"));
        }
        if user.is_builtin {
            return Err(AppError::bad_request("the built-in administrator must keep the admin role"));
        }
        let target_roles = state.app.storage.role_codes_for_user(user.id.clone()).await.unwrap_or_default();
        if permissions_for_roles(&target_roles).iter().any(|permission| permission.starts_with("admin:")) {
            ensure_can_manage_target(&state, &actor, &user.id).await?;
        }
        for existing in target_roles {
            state.app.storage.unbind_global_role(user.id.clone(), existing).await.map_err(AppError::from)?;
        }
        state.app.storage.revoke_user_sessions(user.id.clone()).await.map_err(AppError::from)?;
        state.drop_user_sessions(&user.id).await;
    } else if body.role.is_some() || body.scope.is_some() {
        // A lower-privileged administrator may manage data users, but must not
        // demote or rewrite an account with administrative permissions.
        let target_roles = state.app.storage.role_codes_for_user(user.id.clone()).await.unwrap_or_default();
        if permissions_for_roles(&target_roles).iter().any(|permission| permission.starts_with("admin:")) {
            ensure_can_manage_target(&state, &actor, &user.id).await?;
        }
        // `bindings_for_user` also synthesizes asset grants. A global role edit
        // must not reuse one of those as its scope: an asset-only user should
        // gain a real global role, not another table grant.
        let existing_bindings = state.app.storage.bindings_for_user(user.id.clone()).await.unwrap_or_default();
        let global_binding = existing_bindings.iter().find(|binding| binding.scope_type == "global");
        let role_code = body
            .role
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            // Preserve the legacy scope-only update path, which used the
            // current role, while keeping the *scope* fallback global-only.
            .or_else(|| existing_bindings.first().map(|binding| binding.role_code.clone()))
            .ok_or_else(|| AppError::bad_request("role is required"))?;
        role_permission_codes(&role_code)?;
        if user.is_builtin && role_code != "admin" {
            return Err(AppError::bad_request("the built-in administrator must keep the admin role"));
        }
        // Keep the existing global scope unless a new one is supplied.
        let fallback_scope = global_binding
            .map(|binding| ScopeInput { scope_type: binding.scope_type.clone(), scope_id: binding.scope_id.clone() });
        let (scope_type, scope_id) = validate_scope(&state, body.scope.as_ref().or(fallback_scope.as_ref())).await?;
        if scope_type == "global" {
            ensure_can_assign_global_role(&actor, &role_code)?;
        } else {
            let grant = grant_from_scope(&user.id, &role_code, &scope_type, scope_id.as_deref(), Some(&actor.id))
                .ok_or_else(|| AppError::bad_request("invalid scope"))?;
            ensure_can_grant_asset(&state, &actor, &grant).await?;
        }
        for existing in state.app.storage.role_codes_for_user(user.id.clone()).await.unwrap_or_default() {
            state.app.storage.unbind_global_role(user.id.clone(), existing).await.map_err(AppError::from)?;
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
    let asset_roles = state.app.storage.asset_role_codes_for_user(refreshed.id.clone()).await.unwrap_or_default();
    let mut effective_roles = roles.clone();
    effective_roles.extend(asset_roles.clone());
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
    let permissions = dbx_core::identity::permissions_for_roles(&roles);
    Ok(Json(UserView {
        effective_permissions: dbx_core::identity::permissions_for_roles(&effective_roles),
        permissions,
        asset_roles,
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
    ensure_can_manage_target(&state, &actor, &user.id).await?;
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

#[derive(Debug, Serialize)]
pub struct AssetGrantView {
    pub id: String,
    pub principal_type: String,
    pub principal_id: String,
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
            principal_type: grant.principal_type,
            principal_id: grant.principal_id,
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

/// Resolves a connection's dialect from the runtime cache, falling back to the
/// persisted rows. Self-service requesters can be the first actor to touch a
/// freshly restarted server, when the runtime cache has not been hydrated yet.
async fn connection_db_type_for_validation(
    state: &WebState,
    connection_id: &str,
) -> Result<Option<dbx_core::models::connection::DatabaseType>, AppError> {
    if let Some(config) = state.app.configs.read().await.get(connection_id) {
        return Ok(Some(config.db_type));
    }
    Ok(state
        .app
        .storage
        .load_connections()
        .await
        .map_err(AppError::from)?
        .into_iter()
        .find(|config| config.id == connection_id)
        .map(|config| config.db_type))
}

async fn validate_grant(
    state: &WebState,
    principal_type: &str,
    principal_id: &str,
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
            if connection_db_type_for_validation(state, connection).await?.is_none() {
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
            let Some(db_type) = connection_db_type_for_validation(state, connection).await? else {
                return Err(AppError::bad_request("unknown connection"));
            };
            let is_mongo = db_type == dbx_core::models::connection::DatabaseType::MongoDb;
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
        principal_type: principal_type.to_string(),
        principal_id: principal_id.to_string(),
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
    record_grant_audit_with_details(state, actor, action, grant, serde_json::json!({}));
}

fn record_grant_audit_with_details(
    state: &WebState,
    actor: &Actor,
    action: &str,
    grant: &AssetGrant,
    extra: serde_json::Value,
) {
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
    let mut details = serde_json::json!({
        "action": action,
        "principal_type": grant.principal_type,
        "principal_id": grant.principal_id,
        "role_code": grant.role_code,
        "target_kind": grant.target_kind.as_str(),
        "connection_id": grant.connection_id,
        "database_name": grant.database_name,
        "schema_name": grant.schema_name,
        "table_name": grant.table_name,
    });
    if let (Some(target), Some(extra)) = (details.as_object_mut(), extra.as_object()) {
        for (key, value) in extra {
            target.insert(key.clone(), value.clone());
        }
    }
    event.details_json = Some(details.to_string());
    state.app.record_audit(event);
}

pub async fn list_bindings(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Path(user_id): Path<String>,
) -> Result<Json<Vec<AssetGrantView>>, AppError> {
    require(&actor, Permission::AdminUsers)?;
    // Effective access, including grants inherited from access groups. Group
    // rows are read-only here; they are edited on the group itself.
    let grants = state.app.storage.effective_asset_grants_for_user(user_id).await.map_err(AppError::from)?;
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
    let grant = validate_grant(&state, "user", &user_id, &actor, body).await?;
    ensure_can_grant_asset(&state, &actor, &grant).await?;
    state.app.storage.create_asset_grant(grant.clone()).await.map_err(AppError::from)?;
    state.refresh_user_authorization(&grant.principal_id).await;
    record_grant_audit(&state, &actor, "created", &grant);
    Ok(Json(AssetGrantView::from(grant)))
}

#[derive(Debug, Deserialize)]
pub struct UpdateGrantRequest {
    #[serde(default)]
    pub role_code: Option<String>,
    /// `null` clears the expiry; an absent field leaves it unchanged.
    #[serde(default, deserialize_with = "deserialize_some")]
    pub expires_at: Option<Option<String>>,
    #[serde(default)]
    pub reason: Option<String>,
}

fn deserialize_some<'de, T, D>(deserializer: D) -> Result<Option<T>, D::Error>
where
    T: Deserialize<'de>,
    D: Deserializer<'de>,
{
    T::deserialize(deserializer).map(Some)
}

/// Applies the editable grant fields after the caller has verified ownership.
async fn apply_grant_update(
    state: &WebState,
    actor: &Actor,
    mut grant: AssetGrant,
    body: UpdateGrantRequest,
) -> Result<AssetGrant, AppError> {
    if let Some(role_code) = body.role_code.as_deref().map(str::trim).filter(|value| !value.is_empty()) {
        grant.role_code = role_code.to_string();
    }
    if let Some(expires_at) = body.expires_at {
        grant.expires_at = expires_at.and_then(|value| {
            let value = value.trim().to_string();
            (!value.is_empty()).then_some(value)
        });
    }
    if let Some(reason) = body.reason {
        grant.reason = reason.trim().to_string();
    }
    role_permission_codes(&grant.role_code)?;
    if let Some(expires) = grant.expires_at.as_deref() {
        let parsed = chrono::DateTime::parse_from_rfc3339(expires)
            .map_err(|_| AppError::bad_request("expires_at must be an RFC3339 timestamp"))?;
        if parsed.timestamp_millis() <= chrono::Utc::now().timestamp_millis() {
            return Err(AppError::bad_request("expires_at must be in the future"));
        }
    }
    ensure_can_grant_asset(state, actor, &grant).await?;
    grant.updated_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    if !state.app.storage.update_asset_grant(grant.clone()).await.map_err(AppError::from)? {
        return Err(AppError::not_found("binding not found"));
    }
    Ok(grant)
}

pub async fn update_binding(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Path((user_id, binding_id)): Path<(String, String)>,
    Json(body): Json<UpdateGrantRequest>,
) -> Result<Json<AssetGrantView>, AppError> {
    require(&actor, Permission::AdminUsers)?;
    let grant = state
        .app
        .storage
        .asset_grant_by_id(binding_id)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("binding not found"))?;
    if grant.principal_type != "user" || grant.principal_id != user_id {
        return Err(AppError::not_found("binding not found"));
    }
    let grant = apply_grant_update(&state, &actor, grant, body).await?;
    state.refresh_user_authorization(&grant.principal_id).await;
    record_grant_audit(&state, &actor, "updated", &grant);
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
    if grant.principal_type != "user" || grant.principal_id != user_id {
        return Err(AppError::not_found("binding not found"));
    }
    // Compute coverage while the grant still exists so the dialog/response can
    // tell the administrator what remains; the grant itself is excluded.
    let coverage = grant_coverage_without(&state, &grant).await?;
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    if !state.app.storage.delete_asset_grant(binding_id.clone(), user_id.clone()).await.map_err(AppError::from)? {
        return Err(AppError::not_found("binding not found"));
    }
    let revoked_requests =
        state.app.storage.revoke_access_requests_for_grant(binding_id.clone(), now).await.map_err(AppError::from)?;
    state.refresh_user_authorization(&grant.principal_id).await;
    record_grant_audit_with_details(
        &state,
        &actor,
        "deleted",
        &grant,
        serde_json::json!({
            "access_request_ids": coverage.access_request_ids.clone(),
            "still_covered": coverage.still_covered,
            "remaining_grant_ids": coverage.remaining_grants.iter().map(|grant| grant.id.clone()).collect::<Vec<_>>(),
        }),
    );
    for request in &revoked_requests {
        record_access_request_audit(
            &state,
            &actor,
            "revoked",
            request,
            AuditOutcome::Success,
            serde_json::json!({
                "grant_id": binding_id,
                "still_covered": coverage.still_covered,
            }),
        );
    }
    let revoked_request_ids: Vec<String> = revoked_requests.iter().map(|request| request.id.clone()).collect();
    Ok(Json(serde_json::json!({
        "ok": true,
        "coverage": coverage,
        "revoked_access_request_ids": revoked_request_ids,
    })))
}

// ---------------------------------------------------------------------------
// Access groups: named user sets that can hold asset grants without gaining a
// global role. Group membership only contributes the grants attached to the
// group; it never adds a global role.
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct AssetGroupView {
    pub id: String,
    pub name: String,
    pub description: String,
    pub created_by: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub member_count: i64,
    pub grant_count: i64,
}

impl From<dbx_core::governance::assets::AssetGroupSummary> for AssetGroupView {
    fn from(summary: dbx_core::governance::assets::AssetGroupSummary) -> Self {
        Self {
            id: summary.group.id,
            name: summary.group.name,
            description: summary.group.description,
            created_by: summary.group.created_by,
            created_at: summary.group.created_at,
            updated_at: summary.group.updated_at,
            member_count: summary.member_count,
            grant_count: summary.grant_count,
        }
    }
}

impl From<dbx_core::governance::assets::AssetGroup> for AssetGroupView {
    fn from(group: dbx_core::governance::assets::AssetGroup) -> Self {
        Self {
            id: group.id,
            name: group.name,
            description: group.description,
            created_by: group.created_by,
            created_at: group.created_at,
            updated_at: group.updated_at,
            member_count: 0,
            grant_count: 0,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct AssetGroupMemberView {
    pub user_id: String,
    pub email: String,
    pub display_name: String,
    pub status: String,
    pub added_by: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct AssetGroupDetailView {
    pub group: AssetGroupView,
    pub members: Vec<AssetGroupMemberView>,
    pub grants: Vec<AssetGrantView>,
}

#[derive(Debug, Deserialize)]
pub struct AssetGroupInput {
    pub name: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Deserialize)]
pub struct AssetGroupMemberInput {
    pub user_id: String,
}

fn validate_group_name(name: &str) -> Result<String, AppError> {
    let name = name.trim();
    if name.is_empty() {
        return Err(AppError::bad_request("group name is required"));
    }
    if name.chars().count() > 120 {
        return Err(AppError::bad_request("group name must be at most 120 characters"));
    }
    Ok(name.to_string())
}

fn map_group_write_error(error: String) -> AppError {
    if error.contains("UNIQUE") {
        AppError::conflict("ASSET_GROUP_EXISTS: an access group with this name already exists")
    } else {
        AppError::from(error)
    }
}

/// Group membership and group grants affect every member. Refresh their
/// in-memory session authorization instead of signing them out.
async fn refresh_group_member_authorization(state: &WebState, group_id: &str) {
    let Ok(members) = state.app.storage.asset_group_members(group_id.to_string()).await else {
        return;
    };
    for member in members {
        state.refresh_user_authorization(&member.user_id).await;
    }
}

fn record_group_audit(state: &WebState, actor: &Actor, action: &str, group: &dbx_core::governance::assets::AssetGroup) {
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
    event.resource_type = Some("asset_group".to_string());
    event.resource_id = Some(group.id.clone());
    event.details_json = Some(
        serde_json::json!({
            "action": action,
            "name": group.name,
        })
        .to_string(),
    );
    state.app.record_audit(event);
}

async fn load_group(state: &WebState, group_id: &str) -> Result<dbx_core::governance::assets::AssetGroup, AppError> {
    state
        .app
        .storage
        .asset_group_by_id(group_id.to_string())
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("access group not found"))
}

pub async fn list_asset_groups(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
) -> Result<Json<Vec<AssetGroupView>>, AppError> {
    require(&actor, Permission::AdminUsers)?;
    let groups = state.app.storage.list_asset_group_summaries().await.map_err(AppError::from)?;
    Ok(Json(groups.into_iter().map(AssetGroupView::from).collect()))
}

pub async fn create_asset_group(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Json(body): Json<AssetGroupInput>,
) -> Result<Json<AssetGroupView>, AppError> {
    require(&actor, Permission::AdminUsers)?;
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let group = dbx_core::governance::assets::AssetGroup {
        id: uuid::Uuid::new_v4().to_string(),
        name: validate_group_name(&body.name)?,
        description: body.description.trim().to_string(),
        created_by: Some(actor.id.clone()),
        created_at: now.clone(),
        updated_at: now,
    };
    state.app.storage.create_asset_group(group.clone()).await.map_err(map_group_write_error)?;
    record_group_audit(&state, &actor, "created", &group);
    Ok(Json(AssetGroupView::from(group)))
}

pub async fn update_asset_group(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Path(group_id): Path<String>,
    Json(body): Json<AssetGroupInput>,
) -> Result<Json<AssetGroupView>, AppError> {
    require(&actor, Permission::AdminUsers)?;
    let mut group = load_group(&state, &group_id).await?;
    group.name = validate_group_name(&body.name)?;
    group.description = body.description.trim().to_string();
    group.updated_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    if !state
        .app
        .storage
        .update_asset_group(group.id.clone(), group.name.clone(), group.description.clone(), group.updated_at.clone())
        .await
        .map_err(map_group_write_error)?
    {
        return Err(AppError::not_found("access group not found"));
    }
    record_group_audit(&state, &actor, "updated", &group);
    Ok(Json(AssetGroupView::from(group)))
}

pub async fn get_asset_group(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Path(group_id): Path<String>,
) -> Result<Json<AssetGroupDetailView>, AppError> {
    require(&actor, Permission::AdminUsers)?;
    let group = load_group(&state, &group_id).await?;
    let users: HashMap<String, _> = state
        .app
        .storage
        .list_users()
        .await
        .map_err(AppError::from)?
        .into_iter()
        .map(|user| (user.id.clone(), user))
        .collect();
    let members = state
        .app
        .storage
        .asset_group_members(group_id.clone())
        .await
        .map_err(AppError::from)?
        .into_iter()
        .map(|member| {
            let user = users.get(&member.user_id);
            AssetGroupMemberView {
                user_id: member.user_id,
                email: user.map(|user| user.email.clone()).unwrap_or_default(),
                display_name: user.map(|user| user.display_name.clone()).unwrap_or_default(),
                status: user.map(|user| user.status.clone()).unwrap_or_default(),
                added_by: member.added_by,
                created_at: member.created_at,
            }
        })
        .collect();
    let grants = state
        .app
        .storage
        .asset_grants_for_group(group_id)
        .await
        .map_err(AppError::from)?
        .into_iter()
        .map(AssetGrantView::from)
        .collect();
    Ok(Json(AssetGroupDetailView { group: AssetGroupView::from(group), members, grants }))
}

pub async fn delete_asset_group(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Path(group_id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    require(&actor, Permission::AdminUsers)?;
    let group = load_group(&state, &group_id).await?;
    refresh_group_member_authorization(&state, &group_id).await;
    if !state.app.storage.delete_asset_group(group_id).await.map_err(AppError::from)? {
        return Err(AppError::not_found("access group not found"));
    }
    record_group_audit(&state, &actor, "deleted", &group);
    Ok(Json(serde_json::json!({ "ok": true })))
}

pub async fn add_asset_group_member(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Path(group_id): Path<String>,
    Json(body): Json<AssetGroupMemberInput>,
) -> Result<Json<serde_json::Value>, AppError> {
    require(&actor, Permission::AdminUsers)?;
    load_group(&state, &group_id).await?;
    let user_id = body.user_id.trim().to_string();
    if user_id.is_empty() {
        return Err(AppError::bad_request("user_id is required"));
    }
    state
        .app
        .storage
        .user_by_id(user_id.clone())
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("user not found"))?;
    let added = state
        .app
        .storage
        .add_asset_group_member(group_id.clone(), user_id.clone(), Some(actor.id.clone()))
        .await
        .map_err(AppError::from)?;
    if added {
        state.refresh_user_authorization(&user_id).await;
    }
    Ok(Json(serde_json::json!({ "ok": true, "added": added })))
}

pub async fn remove_asset_group_member(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Path((group_id, user_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, AppError> {
    require(&actor, Permission::AdminUsers)?;
    load_group(&state, &group_id).await?;
    if !state.app.storage.remove_asset_group_member(group_id, user_id.clone()).await.map_err(AppError::from)? {
        return Err(AppError::not_found("group member not found"));
    }
    state.refresh_user_authorization(&user_id).await;
    Ok(Json(serde_json::json!({ "ok": true })))
}

pub async fn create_group_binding(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Path(group_id): Path<String>,
    Json(body): Json<CreateGrantRequest>,
) -> Result<Json<AssetGrantView>, AppError> {
    require(&actor, Permission::AdminUsers)?;
    load_group(&state, &group_id).await?;
    let grant = validate_grant(&state, "group", &group_id, &actor, body).await?;
    ensure_can_grant_asset(&state, &actor, &grant).await?;
    state.app.storage.create_asset_grant(grant.clone()).await.map_err(AppError::from)?;
    refresh_group_member_authorization(&state, &group_id).await;
    record_grant_audit(&state, &actor, "created", &grant);
    Ok(Json(AssetGrantView::from(grant)))
}

pub async fn update_group_binding(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Path((group_id, binding_id)): Path<(String, String)>,
    Json(body): Json<UpdateGrantRequest>,
) -> Result<Json<AssetGrantView>, AppError> {
    require(&actor, Permission::AdminUsers)?;
    load_group(&state, &group_id).await?;
    let grant = state
        .app
        .storage
        .asset_grant_by_id(binding_id)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("binding not found"))?;
    if grant.principal_type != "group" || grant.principal_id != group_id {
        return Err(AppError::not_found("binding not found"));
    }
    let grant = apply_grant_update(&state, &actor, grant, body).await?;
    refresh_group_member_authorization(&state, &group_id).await;
    record_grant_audit(&state, &actor, "updated", &grant);
    Ok(Json(AssetGrantView::from(grant)))
}

pub async fn delete_group_binding(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Path((group_id, binding_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, AppError> {
    require(&actor, Permission::AdminUsers)?;
    load_group(&state, &group_id).await?;
    let grant = state
        .app
        .storage
        .asset_grant_by_id(binding_id.clone())
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("binding not found"))?;
    if grant.principal_type != "group" || grant.principal_id != group_id {
        return Err(AppError::not_found("binding not found"));
    }
    if !state.app.storage.delete_asset_grant_for_group(binding_id, group_id.clone()).await.map_err(AppError::from)? {
        return Err(AppError::not_found("binding not found"));
    }
    refresh_group_member_authorization(&state, &group_id).await;
    record_grant_audit(&state, &actor, "deleted", &grant);
    Ok(Json(serde_json::json!({ "ok": true })))
}

// ---------------------------------------------------------------------------
// Self-service access requests
// ---------------------------------------------------------------------------

const ACCESS_REQUEST_MAX_HOURS: i64 = 720;
const ACCESS_REQUEST_DEFAULT_LIMIT: i64 = 200;
const ACCESS_REQUEST_MAX_LIMIT: i64 = 500;

#[derive(Debug, Deserialize)]
pub struct CreateAccessRequestInput {
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
    pub duration_hours: i64,
    #[serde(default)]
    pub justification: String,
    /// Submit even when an active grant already covers the same access. The
    /// first submission is refused with ACCESS_ALREADY_GRANTED so the client can
    /// warn that the new window will stack on top of the existing one.
    #[serde(default)]
    pub force: bool,
}

#[derive(Debug, Default, Deserialize)]
pub struct AccessRequestListQuery {
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub limit: Option<i64>,
}

#[derive(Debug, Default, Deserialize)]
pub struct AccessRequestDecisionInput {
    #[serde(default)]
    pub note: String,
}

#[derive(Debug, Serialize)]
pub struct AccessRequestView {
    pub id: String,
    pub requester_id: String,
    pub requester_name: String,
    pub requester_email: String,
    pub role_code: String,
    pub role_name: String,
    pub target_kind: String,
    pub connection_group_id: Option<String>,
    pub connection_id: Option<String>,
    pub connection_name: Option<String>,
    pub group_name: Option<String>,
    pub database_name: Option<String>,
    pub schema_name: Option<String>,
    pub table_name: Option<String>,
    pub name_pattern: bool,
    pub duration_hours: i64,
    pub expires_at: String,
    pub justification: String,
    pub status: String,
    pub decided_by: Option<String>,
    pub decided_by_name: Option<String>,
    pub decided_at: Option<String>,
    pub decision_note: String,
    pub grant_id: Option<String>,
    /// Current state of the grant created by this approval: active, expired,
    /// revoked (the request status is revoked), or missing (the grant row was
    /// removed before this status existed). None when no grant was created.
    pub grant_status: Option<String>,
    /// Administrators who can actually decide this pending request (they hold
    /// `admin:users` and cover the requested role at its target). Empty for
    /// decided requests.
    pub approver_names: Vec<String>,
    pub created_at: String,
    pub expired: bool,
}

struct ApproverCandidate {
    id: String,
    name: String,
    snapshot: AssetScopeSnapshot,
}

#[derive(Default)]
struct AccessRequestLookup {
    user_names: HashMap<String, String>,
    user_emails: HashMap<String, String>,
    connection_names: HashMap<String, String>,
    group_names: HashMap<String, String>,
    role_names: HashMap<String, String>,
    grants_by_id: HashMap<String, AssetGrant>,
    approvers: Vec<ApproverCandidate>,
}

async fn access_request_lookup(state: &WebState) -> Result<AccessRequestLookup, AppError> {
    let mut lookup = AccessRequestLookup::default();
    let users = state.app.storage.list_users().await.map_err(AppError::from)?;
    for user in &users {
        lookup.user_names.insert(user.id.clone(), user.display_name.clone());
        lookup.user_emails.insert(user.id.clone(), user.email.clone());
    }
    // Eligible approvers are resolved once per lookup: global `admin:users`
    // holders whose own snapshot covers the role permissions being requested.
    // The requested target is checked later per request.
    for user in users.iter().filter(|user| user.is_active()) {
        let roles = state.app.storage.role_codes_for_user(user.id.clone()).await.unwrap_or_default();
        if !has_permission(&roles, Permission::AdminUsers) {
            continue;
        }
        if let Ok(snapshot) = load_asset_snapshot(&state.app, &user.id).await {
            lookup.approvers.push(ApproverCandidate { id: user.id.clone(), name: user.display_name.clone(), snapshot });
        }
    }
    for connection in state.app.storage.load_connections().await.map_err(AppError::from)? {
        lookup.connection_names.insert(connection.id, connection.name);
    }
    for group in state.app.storage.list_connection_groups().await.map_err(AppError::from)? {
        lookup.group_names.insert(group.id, group.name);
    }
    for role in BuiltinRole::ALL {
        lookup.role_names.insert(role.code().to_string(), role.name().to_string());
    }
    for role in state.app.storage.list_custom_roles().await.map_err(AppError::from)? {
        lookup.role_names.insert(role.code, role.name);
    }
    for grant in state.app.storage.list_all_asset_grants().await.map_err(AppError::from)? {
        lookup.grants_by_id.insert(grant.id.clone(), grant);
    }
    Ok(lookup)
}

fn grant_status_for(request: &AccessRequest, lookup: &AccessRequestLookup, now: &str) -> Option<String> {
    if request.status == AccessRequestStatus::Revoked {
        return Some("revoked".to_string());
    }
    let grant_id = request.grant_id.as_deref()?;
    match lookup.grants_by_id.get(grant_id) {
        None => Some("missing".to_string()),
        Some(grant) => Some(if grant.expires_at.as_deref().is_some_and(|expires| expires <= now) {
            "expired".to_string()
        } else {
            "active".to_string()
        }),
    }
}

/// What remains after a grant is removed. Computed against the user's snapshot
/// with the grant filtered out, so the preview and the post-delete result agree.
#[derive(Debug, Serialize)]
pub struct GrantCoverageView {
    pub grant_id: String,
    pub still_covered: bool,
    pub missing_permissions: Vec<String>,
    pub via_global_roles: bool,
    pub remaining_grants: Vec<AssetGrantView>,
    /// Approved access requests backed by this grant.
    pub access_request_ids: Vec<String>,
}

async fn grant_coverage_without(state: &WebState, grant: &AssetGrant) -> Result<GrantCoverageView, AppError> {
    let mut snapshot = load_asset_snapshot(&state.app, &grant.principal_id).await.map_err(AppError::from)?;
    snapshot.grants.retain(|candidate| candidate.id != grant.id);
    let required = asset_permissions_for_role(&grant.role_code).unwrap_or_else(|_| Vec::new());
    let missing_permissions: Vec<String> = required
        .iter()
        .filter(|permission| !actor_covers_grant(&snapshot, grant, **permission))
        .map(|permission| permission.as_str().to_string())
        .collect();
    let via_global_roles =
        !required.is_empty() && required.iter().all(|permission| snapshot.has_global_permission(permission.as_str()));
    let remaining_grants: Vec<AssetGrantView> = snapshot
        .grants
        .iter()
        .filter(|candidate| required.iter().any(|permission| role_grants_permission(&candidate.role_code, *permission)))
        .cloned()
        .map(AssetGrantView::from)
        .collect();
    let requests = state.app.storage.access_requests_for_grant(grant.id.clone()).await.map_err(AppError::from)?;
    let access_request_ids = requests
        .iter()
        .filter(|request| request.status == AccessRequestStatus::Approved)
        .map(|request| request.id.clone())
        .collect();
    Ok(GrantCoverageView {
        grant_id: grant.id.clone(),
        still_covered: !required.is_empty() && missing_permissions.is_empty(),
        missing_permissions,
        via_global_roles,
        remaining_grants,
        access_request_ids,
    })
}

/// Preview used by the revoke confirmation dialog: "what will the user still
/// be able to do through other grants or global roles?"
pub async fn grant_coverage_preview(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Path((user_id, binding_id)): Path<(String, String)>,
) -> Result<Json<GrantCoverageView>, AppError> {
    require(&actor, Permission::AdminUsers)?;
    let grant = state
        .app
        .storage
        .asset_grant_by_id(binding_id)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("binding not found"))?;
    if grant.principal_type != "user" || grant.principal_id != user_id {
        return Err(AppError::not_found("binding not found"));
    }
    Ok(Json(grant_coverage_without(&state, &grant).await?))
}

fn access_request_view(request: AccessRequest, lookup: &AccessRequestLookup) -> AccessRequestView {
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let approver_names = pending_approver_names(&request, lookup);
    let grant_status = grant_status_for(&request, lookup, &now);
    AccessRequestView {
        id: request.id,
        requester_name: lookup
            .user_names
            .get(&request.requester_id)
            .cloned()
            .unwrap_or_else(|| request.requester_id.clone()),
        requester_email: lookup.user_emails.get(&request.requester_id).cloned().unwrap_or_default(),
        requester_id: request.requester_id,
        role_name: lookup.role_names.get(&request.role_code).cloned().unwrap_or_else(|| request.role_code.clone()),
        role_code: request.role_code,
        target_kind: request.target_kind.as_str().to_string(),
        connection_group_id: request.connection_group_id.clone(),
        group_name: request.connection_group_id.as_ref().and_then(|group| lookup.group_names.get(group).cloned()),
        connection_id: request.connection_id.clone(),
        connection_name: request.connection_id.as_ref().and_then(|id| lookup.connection_names.get(id).cloned()),
        database_name: request.database_name,
        schema_name: request.schema_name,
        table_name: request.table_name,
        name_pattern: request.name_pattern,
        duration_hours: request.duration_hours,
        expired: request.expires_at <= now,
        expires_at: request.expires_at,
        justification: request.justification,
        status: request.status.as_str().to_string(),
        decided_by_name: request.decided_by.as_ref().and_then(|id| lookup.user_names.get(id).cloned()),
        decided_by: request.decided_by,
        decided_at: request.decided_at,
        decision_note: request.decision_note,
        grant_id: request.grant_id,
        grant_status,
        approver_names,
        created_at: request.created_at,
    }
}

/// Builds the grant an approval would create. Kept separate so the list view's
/// eligible-approver calculation and the approve handler use exactly the same
/// target/permission shape.
pub(crate) fn access_request_grant(request: &AccessRequest, id: String, granted_by: Option<String>) -> AssetGrant {
    AssetGrant {
        id,
        principal_type: "user".to_string(),
        principal_id: request.requester_id.clone(),
        role_code: request.role_code.clone(),
        target_kind: request.target_kind,
        connection_group_id: request.connection_group_id.clone(),
        connection_id: request.connection_id.clone(),
        database_name: request.database_name.clone(),
        schema_name: request.schema_name.clone(),
        table_name: request.table_name.clone(),
        name_pattern: request.name_pattern,
        expires_at: Some(request.expires_at.clone()),
        granted_by,
        reason: format!("Access request: {}", request.justification),
        created_at: String::new(),
        updated_at: String::new(),
    }
}

pub(crate) fn access_request_required_permissions(role_code: &str) -> Vec<Permission> {
    asset_permissions_for_role(role_code).unwrap_or_default()
}

pub(crate) fn snapshot_covers_access_request(snapshot: &AssetScopeSnapshot, request: &AccessRequest) -> bool {
    let required = access_request_required_permissions(&request.role_code);
    if required.is_empty() {
        return false;
    }
    let grant = access_request_grant(request, String::new(), None);
    required.iter().all(|permission| actor_covers_grant(snapshot, &grant, *permission))
}

fn pending_approver_names(request: &AccessRequest, lookup: &AccessRequestLookup) -> Vec<String> {
    if request.status != AccessRequestStatus::Pending {
        return Vec::new();
    }
    let mut names: Vec<String> = lookup
        .approvers
        .iter()
        .filter(|candidate| candidate.id != request.requester_id)
        .filter(|candidate| snapshot_covers_access_request(&candidate.snapshot, request))
        .map(|candidate| candidate.name.clone())
        .collect();
    names.sort();
    names.dedup();
    names
}

fn record_access_request_audit(
    state: &WebState,
    actor: &Actor,
    action: &str,
    request: &AccessRequest,
    outcome: AuditOutcome,
    extra: serde_json::Value,
) {
    let context = dbx_core::audit::current_audit_context().unwrap_or_else(|| AuditContext {
        actor: actor.clone(),
        source: AuditSource::Web,
        client_ip: None,
        user_agent: None,
        request_id: None,
        execution_id: None,
    });
    let mut event = AuditEventInsert::new(&context, AuditOperation::Admin, AuditDecision::Allowed, outcome);
    event.resource_type = Some("access_request".to_string());
    event.resource_id = Some(request.id.clone());
    let mut details = serde_json::json!({
        "action": action,
        "requester_id": request.requester_id,
        "role_code": request.role_code,
        "target_kind": request.target_kind.as_str(),
        "connection_id": request.connection_id,
        "database_name": request.database_name,
        "schema_name": request.schema_name,
        "table_name": request.table_name,
        "status": request.status.as_str(),
    });
    if let (Some(details), Some(extra)) = (details.as_object_mut(), extra.as_object()) {
        details.extend(extra.clone());
    }
    event.details_json = Some(details.to_string());
    state.app.record_audit(event);
}

fn access_request_scope(actor: &Actor, query: &AccessRequestListQuery) -> Result<bool, AppError> {
    match query.scope.as_deref().unwrap_or("mine") {
        "mine" => Ok(false),
        "all" => {
            require(actor, Permission::AdminUsers)?;
            Ok(true)
        }
        _ => Err(AppError::bad_request("scope must be mine or all")),
    }
}

pub async fn list_access_requests(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Query(query): Query<AccessRequestListQuery>,
) -> Result<Json<Vec<AccessRequestView>>, AppError> {
    let every_user = access_request_scope(&actor, &query)?;
    let status = query
        .status
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            AccessRequestStatus::parse(value)
                .ok_or_else(|| AppError::bad_request("status must be pending, approved, rejected, or cancelled"))
        })
        .transpose()?
        .map(|status| status.as_str().to_string());
    let limit = query.limit.unwrap_or(ACCESS_REQUEST_DEFAULT_LIMIT).clamp(1, ACCESS_REQUEST_MAX_LIMIT);
    let requester = (!every_user).then(|| actor.id.clone());
    let requests = state.app.storage.list_access_requests(requester, status, limit).await.map_err(AppError::from)?;
    let lookup = access_request_lookup(&state).await?;
    Ok(Json(requests.into_iter().map(|request| access_request_view(request, &lookup)).collect()))
}

pub async fn create_access_request(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Json(body): Json<CreateAccessRequestInput>,
) -> Result<Json<AccessRequestView>, AppError> {
    if actor.id.starts_with("system") {
        return Err(AppError::forbidden("system actors cannot request access"));
    }
    if !(1..=ACCESS_REQUEST_MAX_HOURS).contains(&body.duration_hours) {
        return Err(AppError::bad_request(format!("duration_hours must be between 1 and {ACCESS_REQUEST_MAX_HOURS}")));
    }
    let justification = body.justification.trim().to_string();
    if justification.is_empty() {
        return Err(AppError::bad_request("justification is required"));
    }
    let expires_at = (chrono::Utc::now() + chrono::Duration::hours(body.duration_hours))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let grant_body = CreateGrantRequest {
        role_code: body.role_code.clone(),
        target_kind: body.target_kind.clone(),
        connection_group_id: body.connection_group_id.clone(),
        connection_id: body.connection_id.clone(),
        database_name: body.database_name.clone(),
        schema_name: body.schema_name.clone(),
        table_name: body.table_name.clone(),
        name_pattern: body.name_pattern,
        expires_at: Some(expires_at.clone()),
        reason: justification.clone(),
    };
    // Validates the role, target shape, target existence, and expiry.
    let grant = validate_grant(&state, "user", &actor.id, &actor, grant_body).await?;
    if !is_requestable_role(&grant.role_code)? {
        return Err(AppError::bad_request(format!(
            "ROLE_NOT_REQUESTABLE: role '{}' contains permissions that cannot be granted per asset",
            grant.role_code
        )));
    }
    if !body.force {
        let snapshot = load_asset_snapshot(&state.app, &actor.id).await.map_err(AppError::from)?;
        let required = asset_permissions_for_role(&grant.role_code)?;
        let already_covered = !required.is_empty()
            && required.iter().all(|permission| actor_covers_grant(&snapshot, &grant, *permission));
        if already_covered {
            let existing = snapshot
                .grants
                .iter()
                .filter(|candidate| same_grant_target(candidate, &grant))
                .max_by(|left, right| left.expires_at.cmp(&right.expires_at));
            let source = match existing {
                Some(existing) => {
                    format!("until {} (grant {})", existing.expires_at.as_deref().unwrap_or("no expiry"), existing.id)
                }
                None => "through a global role".to_string(),
            };
            return Err(AppError::conflict(format!(
                "ACCESS_ALREADY_GRANTED: this role is already effective for the requested target {source}; resubmit with force=true to request an additional window"
            )));
        }
    }
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let request = AccessRequest {
        id: uuid::Uuid::new_v4().to_string(),
        requester_id: actor.id.clone(),
        role_code: grant.role_code,
        target_kind: grant.target_kind,
        connection_group_id: grant.connection_group_id,
        connection_id: grant.connection_id,
        database_name: grant.database_name,
        schema_name: grant.schema_name,
        table_name: grant.table_name,
        name_pattern: grant.name_pattern,
        duration_hours: body.duration_hours,
        expires_at,
        justification,
        status: AccessRequestStatus::Pending,
        decided_by: None,
        decided_at: None,
        decision_note: String::new(),
        grant_id: None,
        created_at: now.clone(),
        updated_at: now,
    };
    if state.app.storage.pending_access_request_exists(request.clone()).await.map_err(AppError::from)? {
        return Err(AppError::conflict("ACCESS_REQUEST_EXISTS: an identical request is already pending"));
    }
    state.app.storage.create_access_request(request.clone()).await.map_err(AppError::from)?;
    record_access_request_audit(&state, &actor, "created", &request, AuditOutcome::Success, serde_json::json!({}));
    let lookup = access_request_lookup(&state).await?;
    Ok(Json(access_request_view(request, &lookup)))
}

pub async fn cancel_access_request(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Path(request_id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let request = state
        .app
        .storage
        .access_request_by_id(request_id.clone())
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("access request not found"))?;
    if request.requester_id != actor.id {
        return Err(AppError::not_found("access request not found"));
    }
    if request.status != AccessRequestStatus::Pending {
        return Err(AppError::conflict("ACCESS_REQUEST_ALREADY_DECIDED"));
    }
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    if !state.app.storage.cancel_access_request(request_id, actor.id.clone(), now).await.map_err(AppError::from)? {
        return Err(AppError::conflict("ACCESS_REQUEST_ALREADY_DECIDED"));
    }
    record_access_request_audit(&state, &actor, "cancelled", &request, AuditOutcome::Success, serde_json::json!({}));
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn load_pending_access_request(
    state: &WebState,
    actor: &Actor,
    request_id: &str,
) -> Result<AccessRequest, AppError> {
    let request = state
        .app
        .storage
        .access_request_by_id(request_id.to_string())
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("access request not found"))?;
    if request.status != AccessRequestStatus::Pending {
        return Err(AppError::conflict("ACCESS_REQUEST_ALREADY_DECIDED"));
    }
    if request.requester_id == actor.id {
        return Err(AppError::forbidden("ACCESS_REQUEST_SELF_APPROVAL: you cannot decide your own request"));
    }
    Ok(request)
}

pub async fn approve_access_request(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Path(request_id): Path<String>,
    Json(body): Json<AccessRequestDecisionInput>,
) -> Result<Json<AccessRequestView>, AppError> {
    require(&actor, Permission::AdminUsers)?;
    let request = load_pending_access_request(&state, &actor, &request_id).await?;
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    if request.expires_at <= now {
        return Err(AppError::conflict("ACCESS_REQUEST_EXPIRED: the requested window has already ended"));
    }
    let mut grant = access_request_grant(&request, uuid::Uuid::new_v4().to_string(), Some(actor.id.clone()));
    grant.created_at = now.clone();
    grant.updated_at = now.clone();
    ensure_can_grant_asset(&state, &actor, &grant).await?;
    let note = body.note.trim().to_string();
    if !state
        .app
        .storage
        .approve_access_request(request.id.clone(), actor.id.clone(), note.clone(), now.clone(), grant.clone())
        .await
        .map_err(AppError::from)?
    {
        return Err(AppError::conflict("ACCESS_REQUEST_ALREADY_DECIDED"));
    }
    // The grant is visible immediately: refresh the requester's in-memory
    // session authorization instead of forcing a new login. The task-center
    // poll then observes the approved state on its next tick.
    state.refresh_user_authorization(&request.requester_id).await;
    record_grant_audit(&state, &actor, "created", &grant);
    let mut approved = request;
    approved.status = AccessRequestStatus::Approved;
    approved.decided_by = Some(actor.id.clone());
    approved.decided_at = Some(now.clone());
    approved.decision_note = note;
    approved.grant_id = Some(grant.id);
    approved.updated_at = now;
    record_access_request_audit(
        &state,
        &actor,
        "approved",
        &approved,
        AuditOutcome::Success,
        serde_json::json!({ "grant_id": approved.grant_id }),
    );
    let lookup = access_request_lookup(&state).await?;
    Ok(Json(access_request_view(approved, &lookup)))
}

pub async fn reject_access_request(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Path(request_id): Path<String>,
    Json(body): Json<AccessRequestDecisionInput>,
) -> Result<Json<AccessRequestView>, AppError> {
    require(&actor, Permission::AdminUsers)?;
    let request = load_pending_access_request(&state, &actor, &request_id).await?;
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let note = body.note.trim().to_string();
    if !state
        .app
        .storage
        .reject_access_request(request.id.clone(), actor.id.clone(), note.clone(), now.clone())
        .await
        .map_err(AppError::from)?
    {
        return Err(AppError::conflict("ACCESS_REQUEST_ALREADY_DECIDED"));
    }
    let mut rejected = request;
    rejected.status = AccessRequestStatus::Rejected;
    rejected.decided_by = Some(actor.id.clone());
    rejected.decided_at = Some(now.clone());
    rejected.decision_note = note;
    rejected.updated_at = now;
    record_access_request_audit(&state, &actor, "rejected", &rejected, AuditOutcome::Success, serde_json::json!({}));
    let lookup = access_request_lookup(&state).await?;
    Ok(Json(access_request_view(rejected, &lookup)))
}

#[derive(Debug, Serialize)]
pub struct AccessRequestOptionsView {
    pub roles: Vec<AccessRequestRoleOption>,
    pub connections: Vec<AccessRequestConnectionOption>,
    pub connection_groups: Vec<AccessRequestGroupOption>,
    pub max_duration_hours: i64,
}

#[derive(Debug, Serialize)]
pub struct AccessRequestRoleOption {
    pub code: String,
    pub name: String,
    pub permissions: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct AccessRequestConnectionOption {
    pub id: String,
    pub name: String,
    pub db_type: String,
}

#[derive(Debug, Serialize)]
pub struct AccessRequestGroupOption {
    pub id: String,
    pub name: String,
}

/// Options any signed-in user needs to compose a request: requestable roles and
/// the connection/group names they may ask for. No credentials or settings are
/// returned; approval still verifies the connection exists.
pub async fn access_request_options(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
) -> Result<Json<AccessRequestOptionsView>, AppError> {
    let _ = actor;
    let mut roles: Vec<AccessRequestRoleOption> = Vec::new();
    for role in BuiltinRole::ALL {
        if !is_requestable_role(role.code())? {
            continue;
        }
        let permissions = asset_permissions_for_role(role.code())?;
        roles.push(AccessRequestRoleOption {
            code: role.code().to_string(),
            name: role.name().to_string(),
            permissions: permissions.iter().map(|permission| permission.as_str().to_string()).collect(),
        });
    }
    for role in state.app.storage.list_custom_roles().await.map_err(AppError::from)? {
        if !is_requestable_role(&role.code)? {
            continue;
        }
        let permissions = asset_permissions_for_role(&role.code)?;
        roles.push(AccessRequestRoleOption {
            code: role.code,
            name: role.name,
            permissions: permissions.iter().map(|permission| permission.as_str().to_string()).collect(),
        });
    }
    // Least privilege first: Viewer (the narrowest data role) becomes the
    // default option in the requester dialog.
    roles.sort_by_key(|role| role.permissions.len());
    let connections = state
        .app
        .storage
        .load_connections()
        .await
        .map_err(AppError::from)?
        .into_iter()
        .map(|connection| AccessRequestConnectionOption {
            id: connection.id,
            name: connection.name,
            db_type: connection.db_type.as_str().to_string(),
        })
        .collect();
    let connection_groups = state
        .app
        .storage
        .list_connection_groups()
        .await
        .map_err(AppError::from)?
        .into_iter()
        .map(|group| AccessRequestGroupOption { id: group.id, name: group.name })
        .collect();
    Ok(Json(AccessRequestOptionsView {
        roles,
        connections,
        connection_groups,
        max_duration_hours: ACCESS_REQUEST_MAX_HOURS,
    }))
}

#[derive(Debug, Deserialize)]
pub struct EffectiveAccessQuery {
    pub connection_id: String,
    #[serde(default)]
    pub database: Option<String>,
    #[serde(default)]
    pub schema: Option<String>,
    #[serde(default)]
    pub table: Option<String>,
}

#[derive(Serialize)]
pub struct EffectivePermissionView {
    pub permission: String,
    pub allowed: bool,
    pub broad: bool,
    pub grant_ids: Vec<String>,
    pub source: String,
    pub asset_scopeable: bool,
}

#[derive(Serialize)]
pub struct EffectiveAccessView {
    pub user_id: String,
    pub connection_id: String,
    pub database: Option<String>,
    pub schema: Option<String>,
    pub table: Option<String>,
    pub global_roles: Vec<String>,
    pub asset_roles: Vec<String>,
    pub permissions: Vec<EffectivePermissionView>,
    pub can_navigate_connection: bool,
    pub can_navigate_database: bool,
    pub can_navigate_schema: bool,
}

/// Explains the effective decision, including which grants matched. This is
/// the "why can this user do that" view administrators need when debugging an
/// access report; it never executes SQL.
pub async fn effective_access(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Path(user_id): Path<String>,
    Query(query): Query<EffectiveAccessQuery>,
) -> Result<Json<EffectiveAccessView>, AppError> {
    require(&actor, Permission::AdminUsers)?;
    state
        .app
        .storage
        .user_by_id(user_id.clone())
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("user not found"))?;
    let database = clean(query.database);
    let schema = clean(query.schema);
    let table = clean(query.table);
    if table.is_some() && database.is_none() {
        return Err(AppError::bad_request("database is required when table is set"));
    }
    let snapshot = load_asset_snapshot(&state.app, &user_id).await.map_err(AppError::from)?;
    let global_roles = state.app.storage.role_codes_for_user(user_id.clone()).await.map_err(AppError::from)?;
    let asset_roles = state.app.storage.asset_role_codes_for_user(user_id.clone()).await.map_err(AppError::from)?;
    let connection_id = query.connection_id.trim().to_string();
    let mut permissions = Vec::with_capacity(Permission::ALL.len());
    for permission in Permission::ALL {
        let global = snapshot.has_global_permission(permission.as_str());
        let matched = snapshot.permits(
            &connection_id,
            database.as_deref(),
            schema.as_deref(),
            table.as_deref(),
            permission.as_str(),
            false,
        );
        let allowed = matched.is_some();
        permissions.push(EffectivePermissionView {
            permission: permission.as_str().to_string(),
            allowed,
            broad: matched.as_ref().is_some_and(|matched| matched.broad),
            grant_ids: matched.as_ref().map(|matched| matched.grant_ids.clone()).unwrap_or_default(),
            source: if global {
                "global".to_string()
            } else if allowed {
                "grant".to_string()
            } else {
                "none".to_string()
            },
            asset_scopeable: permission.is_asset_scopeable(),
        });
    }
    Ok(Json(EffectiveAccessView {
        user_id,
        connection_id: connection_id.clone(),
        database: database.clone(),
        schema: schema.clone(),
        table,
        global_roles,
        asset_roles,
        permissions,
        can_navigate_connection: snapshot.can_navigate_connection(&connection_id),
        can_navigate_database: database
            .as_deref()
            .is_some_and(|database| snapshot.can_navigate_database(&connection_id, database)),
        can_navigate_schema: database
            .as_deref()
            .zip(schema.as_deref())
            .is_some_and(|(database, schema)| snapshot.can_navigate_schema(&connection_id, database, schema)),
    }))
}

#[derive(Debug, Default, Deserialize)]
pub struct AssetGrantInventoryQuery {
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub connection_id: Option<String>,
    #[serde(default)]
    pub database: Option<String>,
    #[serde(default)]
    pub schema: Option<String>,
    #[serde(default)]
    pub table: Option<String>,
    #[serde(default)]
    pub role_code: Option<String>,
    #[serde(default)]
    pub stale: Option<bool>,
}

#[derive(Serialize)]
pub struct AssetGrantInventoryView {
    pub id: String,
    pub principal_type: String,
    pub principal_id: String,
    pub principal_name: String,
    pub member_count: i64,
    pub user_id: String,
    pub user_email: String,
    pub user_display_name: String,
    pub user_status: String,
    pub role_code: String,
    pub role_name: String,
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
    pub connection_name: Option<String>,
    pub group_name: Option<String>,
    pub expired: bool,
    pub stale_reason: Option<String>,
}

/// Administrative grant inventory. The response is intentionally self-contained
/// (user, role, target labels, validity and stale reasons) so the access view can
/// answer "who can reach this asset" without issuing one request per row.
pub async fn list_asset_grant_inventory(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Query(query): Query<AssetGrantInventoryQuery>,
) -> Result<Json<Vec<AssetGrantInventoryView>>, AppError> {
    require(&actor, Permission::AdminUsers)?;
    let grants = state.app.storage.list_all_asset_grants().await.map_err(AppError::from)?;
    let users = state.app.storage.list_users().await.map_err(AppError::from)?;
    let groups = state.app.storage.list_connection_groups().await.map_err(AppError::from)?;
    let asset_group_summaries = state.app.storage.list_asset_group_summaries().await.map_err(AppError::from)?;
    let asset_group_names: HashMap<String, String> =
        asset_group_summaries.iter().map(|summary| (summary.group.id.clone(), summary.group.name.clone())).collect();
    let mut asset_group_members: HashMap<String, HashSet<String>> = HashMap::new();
    for member in state.app.storage.all_asset_group_members().await.map_err(AppError::from)? {
        asset_group_members.entry(member.group_id).or_default().insert(member.user_id);
    }
    let mut role_names: HashMap<String, String> =
        BuiltinRole::ALL.iter().map(|role| (role.code().to_string(), role.name().to_string())).collect();
    for role in state.app.storage.list_custom_roles().await.map_err(AppError::from)? {
        role_names.insert(role.code, role.name);
    }
    let connection_names: HashMap<String, String> = {
        let configs = state.app.configs.read().await;
        configs.iter().map(|(id, config)| (id.clone(), config.name.clone())).collect()
    };
    let user_map: HashMap<String, _> = users.into_iter().map(|user| (user.id.clone(), user)).collect();
    let group_names: HashMap<String, String> =
        groups.iter().map(|group| (group.id.clone(), group.name.clone())).collect();

    let mut children: HashMap<String, Vec<String>> = HashMap::new();
    let mut direct: HashMap<String, HashSet<String>> = HashMap::new();
    for group in &groups {
        direct.insert(group.id.clone(), group.connection_ids.iter().cloned().collect());
        if let Some(parent) = group.parent_id.as_deref() {
            children.entry(parent.to_string()).or_default().push(group.id.clone());
        }
    }
    let mut group_connections: HashMap<String, HashSet<String>> = HashMap::new();
    for group in &groups {
        let mut pending = vec![group.id.clone()];
        let mut seen = HashSet::new();
        let mut connections = HashSet::new();
        while let Some(id) = pending.pop() {
            if !seen.insert(id.clone()) {
                continue;
            }
            if let Some(members) = direct.get(&id) {
                connections.extend(members.iter().cloned());
            }
            if let Some(descendants) = children.get(&id) {
                pending.extend(descendants.iter().cloned());
            }
        }
        group_connections.insert(group.id.clone(), connections);
    }

    let filter_user = clean(query.user_id);
    let filter_connection = clean(query.connection_id);
    let filter_database = clean(query.database);
    let filter_schema = clean(query.schema);
    let filter_table = clean(query.table);
    let filter_role = clean(query.role_code);
    let stale_only = query.stale.unwrap_or(false);
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let mut results = Vec::new();
    for grant in grants {
        if let Some(user) = filter_user.as_deref() {
            let matches = if grant.principal_type == "group" {
                asset_group_members.get(&grant.principal_id).is_some_and(|members| members.contains(user))
            } else {
                user == grant.principal_id
            };
            if !matches {
                continue;
            }
        }
        if filter_role.as_deref().is_some_and(|role| role != grant.role_code) {
            continue;
        }
        if let Some(connection) = filter_connection.as_deref() {
            let matches = match grant.target_kind {
                AssetTargetKind::ConnectionGroup => grant
                    .connection_group_id
                    .as_deref()
                    .and_then(|group| group_connections.get(group))
                    .is_some_and(|connections| connections.contains(connection)),
                _ => grant.connection_id.as_deref() == Some(connection),
            };
            if !matches {
                continue;
            }
        }
        if let Some(database) = filter_database.as_deref() {
            if grant.database_name.as_deref().is_some_and(|value| !value.eq_ignore_ascii_case(database)) {
                continue;
            }
        }
        if let Some(schema) = filter_schema.as_deref() {
            if grant.schema_name.as_deref().is_some_and(|value| !value.eq_ignore_ascii_case(schema)) {
                continue;
            }
        }
        if let Some(table) = filter_table.as_deref() {
            if !grant.matches_table_name(table) {
                continue;
            }
        }
        let mut stale = Vec::new();
        match grant.target_kind {
            AssetTargetKind::ConnectionGroup => {
                if grant.connection_group_id.as_deref().is_some_and(|group| !group_names.contains_key(group)) {
                    stale.push("connection group no longer exists");
                }
            }
            _ => {
                if grant.connection_id.as_deref().is_some_and(|connection| !connection_names.contains_key(connection)) {
                    stale.push("connection no longer exists");
                }
            }
        }
        if !role_names.contains_key(&grant.role_code) {
            stale.push("role no longer exists");
        } else if asset_permissions_for_role(&grant.role_code).map(|permissions| permissions.is_empty()).unwrap_or(true)
        {
            stale.push("role has no asset permissions");
        }
        if grant.principal_type == "group" {
            if !asset_group_names.contains_key(&grant.principal_id) {
                stale.push("access group no longer exists");
            }
        } else if !user_map.contains_key(&grant.principal_id) {
            stale.push("user no longer exists");
        }
        let stale_reason = (!stale.is_empty()).then(|| stale.join("; "));
        if stale_only && stale_reason.is_none() {
            continue;
        }
        let user = user_map.get(&grant.principal_id);
        let expired = grant.is_expired(&now);
        let principal_name = if grant.principal_type == "group" {
            asset_group_names.get(&grant.principal_id).cloned().unwrap_or_else(|| grant.principal_id.clone())
        } else {
            user.map(|user| user.display_name.clone()).unwrap_or_else(|| grant.principal_id.clone())
        };
        let member_count =
            asset_group_members.get(&grant.principal_id).map(|members| members.len() as i64).unwrap_or(0);
        results.push(AssetGrantInventoryView {
            id: grant.id,
            principal_type: grant.principal_type.clone(),
            principal_id: grant.principal_id.clone(),
            principal_name,
            member_count,
            user_id: grant.principal_id.clone(),
            user_email: user.map(|user| user.email.clone()).unwrap_or_default(),
            user_display_name: user.map(|user| user.display_name.clone()).unwrap_or_default(),
            user_status: user.map(|user| user.status.clone()).unwrap_or_default(),
            role_name: role_names.get(&grant.role_code).cloned().unwrap_or_else(|| grant.role_code.clone()),
            role_code: grant.role_code.clone(),
            target_kind: grant.target_kind.as_str().to_string(),
            connection_name: grant
                .connection_id
                .as_deref()
                .and_then(|connection| connection_names.get(connection).cloned()),
            group_name: grant.connection_group_id.as_deref().and_then(|group| group_names.get(group).cloned()),
            connection_group_id: grant.connection_group_id.clone(),
            connection_id: grant.connection_id.clone(),
            database_name: grant.database_name.clone(),
            schema_name: grant.schema_name.clone(),
            table_name: grant.table_name.clone(),
            name_pattern: grant.name_pattern,
            expires_at: grant.expires_at.clone(),
            granted_by: grant.granted_by.clone(),
            reason: grant.reason.clone(),
            created_at: grant.created_at.clone(),
            expired,
            stale_reason,
        });
    }
    results.sort_by(|left, right| {
        left.principal_name.cmp(&right.principal_name).then_with(|| left.created_at.cmp(&right.created_at))
    });
    Ok(Json(results))
}

#[cfg(test)]
mod tests {
    use super::*;
    use dbx_core::audit::ActorKind;

    fn actor_with_roles(roles: &[&str]) -> Actor {
        Actor {
            id: "actor-1".to_string(),
            display_name: "Actor".to_string(),
            kind: ActorKind::Human,
            roles: roles.iter().map(|role| (*role).to_string()).collect(),
            asset_roles: Vec::new(),
            tenant_id: None,
            session_id: None,
            auth_method: "local_password".to_string(),
        }
    }

    fn grant(role_code: &str, target_kind: AssetTargetKind) -> AssetGrant {
        AssetGrant {
            id: "grant-1".to_string(),
            principal_type: "user".to_string(),
            principal_id: "target-1".to_string(),
            role_code: role_code.to_string(),
            target_kind,
            connection_group_id: None,
            connection_id: Some("conn-1".to_string()),
            database_name: Some("app".to_string()),
            schema_name: Some("public".to_string()),
            table_name: Some("orders".to_string()),
            name_pattern: false,
            expires_at: None,
            granted_by: Some("actor-1".to_string()),
            reason: String::new(),
            created_at: String::new(),
            updated_at: String::new(),
        }
    }

    #[test]
    fn security_admin_cannot_assign_roles_above_its_ceiling() {
        let security_admin = actor_with_roles(&["security_admin"]);
        assert!(ensure_can_assign_global_role(&security_admin, "auditor").is_ok());
        let error = ensure_can_assign_global_role(&security_admin, "admin").unwrap_err();
        assert!(error.to_string().contains("GRANT_CEILING"));
        assert!(ensure_can_assign_global_role(&actor_with_roles(&["admin"]), "admin").is_ok());
    }

    #[test]
    fn security_admin_cannot_create_custom_roles_above_its_ceiling() {
        let security_admin = actor_with_roles(&["security_admin"]);
        assert!(ensure_can_assign_permissions(&security_admin, &["audit:read".to_string()]).is_ok());
        assert!(ensure_can_assign_permissions(&security_admin, &["admin:settings".to_string()]).is_err());
    }

    #[test]
    fn grant_ceiling_requires_existing_coverage() {
        let viewer = grant("viewer", AssetTargetKind::Table);
        let security_admin = actor_with_roles(&["security_admin"]);
        let security_snapshot = AssetScopeSnapshot {
            user_id: security_admin.id.clone(),
            global_roles: security_admin.roles.clone(),
            grants: Vec::new(),
            group_connections: HashMap::new(),
        };
        assert!(!actor_covers_grant(&security_snapshot, &viewer, Permission::QueryRead));

        let dba_snapshot = AssetScopeSnapshot {
            user_id: "actor-2".to_string(),
            global_roles: vec!["dba".to_string()],
            grants: Vec::new(),
            group_connections: HashMap::new(),
        };
        assert!(actor_covers_grant(&dba_snapshot, &viewer, Permission::QueryRead));
    }

    #[test]
    fn roles_without_asset_permissions_are_rejected() {
        assert!(asset_permissions_for_role("auditor").unwrap().is_empty());
        assert!(asset_permissions_for_role("security_admin").unwrap().is_empty());
        assert!(!asset_permissions_for_role("viewer").unwrap().is_empty());
    }

    #[test]
    fn update_grant_request_distinguishes_null_from_absent_expiry() {
        let absent: UpdateGrantRequest = serde_json::from_str("{}").unwrap();
        assert!(absent.expires_at.is_none());
        let cleared: UpdateGrantRequest = serde_json::from_str(r#"{"expires_at":null}"#).unwrap();
        assert_eq!(cleared.expires_at, Some(None));
        let set: UpdateGrantRequest = serde_json::from_str(r#"{"expires_at":"2030-01-01T00:00:00Z"}"#).unwrap();
        assert_eq!(set.expires_at, Some(Some("2030-01-01T00:00:00Z".to_string())));
    }
}
