//! Read-only governance tools for the web AI assistant.
//!
//! The assistant runs as the signed-in actor, so these tools must answer with
//! exactly the rows that actor may already read through the HTTP API. Every
//! definition is filtered by the caller's permissions, and the executor checks
//! them again before touching storage.
//!
//! Nothing here approves, rejects, executes, grants, or publishes. Approval
//! actions stay human-only.

use std::collections::HashMap;
use std::sync::Arc;

use dbx_core::agent_events::ToolDefinition;
use dbx_core::ai::agent_tools::{GovernanceToolExecutor, GovernanceToolset};
use dbx_core::audit::Actor;
use dbx_core::identity::{has_permission, permissions_for_roles, Permission};
use serde_json::{json, Value};

use crate::routes::approvals::{build_approval_detail, build_template_views};
use crate::routes::audit::{query_events_for_actor, AuditEventsQuery};
use crate::routes::my_tasks::build_my_tasks;
use crate::routes::policies::build_effective_policy;
use crate::routes::users::{build_role_views, build_user_views};
use crate::state::WebState;

const MAX_ROWS: usize = 100;

pub fn governance_toolset(state: Arc<WebState>, actor: Actor) -> GovernanceToolset {
    let definitions = tool_definitions(&actor);
    let executor: GovernanceToolExecutor = Arc::new(move |name: String, arguments: Value| {
        let state = state.clone();
        let actor = actor.clone();
        Box::pin(async move { execute(&state, &actor, &name, &arguments).await })
    });
    GovernanceToolset { definitions, executor }
}

/// The tools this actor may use, derived from the same permissions as the HTTP
/// routes. `get_my_*` tools need no governance permission because they only
/// return the actor's own rows.
pub fn tool_definitions(actor: &Actor) -> Vec<ToolDefinition> {
    let mut tools = vec![
        tool(
            "get_my_context",
            "Describe the signed-in user's roles, permissions, asset roles, and asset grants (including expiry). Use this before explaining why an action was denied or what the user can access.",
            json!({"type": "object", "properties": {}, "required": []}),
        ),
        tool(
            "list_my_approvals",
            "List SQL approval tickets visible to the signed-in user. scope=mine (default) returns requests they submitted; scope=pending returns tickets waiting for their vote; scope=all returns both. Results contain status, steps, current approvers, timestamps, and execution errors.",
            json!({
                "type": "object",
                "properties": {
                    "scope": {"type": "string", "enum": ["mine", "pending", "all"]},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 50}
                },
                "required": []
            }),
        ),
        tool(
            "get_my_approval",
            "Get one SQL approval ticket by id from the signed-in user's own or pending list, including the current step, approvers, decisions, and execution error.",
            json!({
                "type": "object",
                "properties": {"approval_id": {"type": "string"}},
                "required": ["approval_id"]
            }),
        ),
        tool(
            "list_my_access_requests",
            "List the signed-in user's self-service access requests (role/asset grants they asked for), with status, target, duration, expiry, and decision details. scope=pending returns access requests waiting for their approval.",
            json!({
                "type": "object",
                "properties": {
                    "scope": {"type": "string", "enum": ["mine", "pending", "all"]},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 50}
                },
                "required": []
            }),
        ),
    ];
    if has_permission(&actor.roles, Permission::QueryRead) {
        tools.push(tool(
            "simulate_policy",
            "Evaluate the active governance rules against a SQL statement without executing it. Returns the decision effect, matched rule ids/reasons, whether approval is required, and the policy bundle hash. The connection must already be open.",
            json!({
                "type": "object",
                "properties": {
                    "connection_id": {"type": "string"},
                    "database": {"type": "string"},
                    "sql": {"type": "string"}
                },
                "required": ["connection_id", "database", "sql"]
            }),
        ));
    }
    if has_permission(&actor.roles, Permission::AuditRead) {
        tools.push(tool(
            "query_audit_events",
            "Query the audit log. Global audit roles see every event; other roles only see their own. Supports actor_id, connection_id, database, operation, decision, outcome, sql_contains, target_contains, from_ms, to_ms, cursor_seq, and limit. Returns events plus the next cursor.",
            json!({
                "type": "object",
                "properties": {
                    "actor_id": {"type": "string"},
                    "connection_id": {"type": "string"},
                    "database": {"type": "string"},
                    "operation": {"type": "string"},
                    "decision": {"type": "string"},
                    "outcome": {"type": "string"},
                    "sql_contains": {"type": "string"},
                    "target_contains": {"type": "string"},
                    "from_ms": {"type": "integer"},
                    "to_ms": {"type": "integer"},
                    "cursor_seq": {"type": "integer"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 100}
                },
                "required": []
            }),
        ));
    }
    if has_permission(&actor.roles, Permission::AdminUsers) {
        tools.extend([
            tool(
                "list_users",
                "List DBX users with status, global roles, asset roles, and effective permissions. Optionally filter by a case-insensitive substring of email or display name. Requires admin:users.",
                json!({
                    "type": "object",
                    "properties": {
                        "q": {"type": "string"},
                        "limit": {"type": "integer", "minimum": 1, "maximum": 200}
                    },
                    "required": []
                }),
            ),
            tool(
                "list_roles",
                "List built-in and custom roles with their permission codes. Requires admin:users.",
                json!({"type": "object", "properties": {}, "required": []}),
            ),
            tool(
                "list_asset_grants",
                "List direct and group asset grants (connection, database, schema, table). Optionally filter by user, connection, role, or expiry. Requires admin:users.",
                json!({
                    "type": "object",
                    "properties": {
                        "user_id": {"type": "string"},
                        "connection_id": {"type": "string"},
                        "role_code": {"type": "string"},
                        "include_expired": {"type": "boolean"},
                        "limit": {"type": "integer", "minimum": 1, "maximum": 200}
                    },
                    "required": []
                }),
            ),
            tool(
                "list_data_policies",
                "List column-masking and row-filter data policies, optionally for one connection. Requires admin:users.",
                json!({
                    "type": "object",
                    "properties": {"connection_id": {"type": "string"}},
                    "required": []
                }),
            ),
        ]);
    }
    tools.push(tool(
        "get_user_permissions",
        "Explain one user's effective access: global roles, asset-scoped roles, global and asset permissions, role bindings, and resolved asset grants. Without user_id it describes the signed-in user; another user requires admin:users.",
        json!({
            "type": "object",
            "properties": {"user_id": {"type": "string"}},
            "required": []
        }),
    ));
    if has_permission(&actor.roles, Permission::ApprovalRead) {
        tools.extend([
            tool(
                "list_approval_templates",
                "List approval templates with scope, steps, approver roles/users, and execution mode. Requires approval:read.",
                json!({"type": "object", "properties": {}, "required": []}),
            ),
            tool(
                "get_approval_flow",
                "Get one approval request's full flow: status, template, every step (mode, approvers, decisions), timestamps, and execution result. Visibility follows the approval API (requester, approver, privileged audit roles, or asset scope).",
                json!({
                    "type": "object",
                    "properties": {"approval_id": {"type": "string"}},
                    "required": ["approval_id"]
                }),
            ),
        ]);
    }
    if has_permission(&actor.roles, Permission::PolicyRead) {
        tools.push(tool(
            "list_policy_rules",
            "List the effective governance policy rules: id, priority, effect, match conditions, message, bound approval template, and the active policy bundle hash. Requires policy:read.",
            json!({"type": "object", "properties": {}, "required": []}),
        ));
    }
    tools
}

fn tool(name: &'static str, description: &'static str, parameters: Value) -> ToolDefinition {
    ToolDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        read_only: true,
        parallel_ok: true,
    }
}

fn require_permission(actor: &Actor, permission: Permission) -> Result<(), String> {
    if has_permission(&actor.roles, permission) {
        Ok(())
    } else {
        Err(format!("PERMISSION_DENIED: {}", permission.as_str()))
    }
}

fn arg_limit(arguments: &Value, default: usize, max: usize) -> usize {
    arguments.get("limit").and_then(Value::as_u64).map(|value| value as usize).unwrap_or(default).clamp(1, max)
}

fn arg_str<'a>(arguments: &'a Value, key: &str) -> Option<&'a str> {
    arguments.get(key).and_then(Value::as_str).map(str::trim).filter(|value| !value.is_empty())
}

async fn execute(state: &WebState, actor: &Actor, name: &str, arguments: &Value) -> Result<String, String> {
    let value = match name {
        "get_my_context" => my_context(state, actor).await?,
        "list_my_approvals" => my_approvals(state, actor, arguments).await?,
        "get_my_approval" => my_approval(state, actor, arguments).await?,
        "list_my_access_requests" => my_access_requests(state, actor, arguments).await?,
        "simulate_policy" => simulate_policy(state, actor, arguments).await?,
        "query_audit_events" => audit_events(state, actor, arguments).await?,
        "list_users" => list_users(state, actor, arguments).await?,
        "list_roles" => {
            require_permission(actor, Permission::AdminUsers)?;
            serde_json::to_value(build_role_views(state, actor).await.map_err(|error| error.to_string())?)
                .map_err(|error| error.to_string())?
        }
        "list_asset_grants" => list_asset_grants(state, actor, arguments).await?,
        "get_user_permissions" => user_permissions(state, actor, arguments).await?,
        "list_approval_templates" => {
            require_permission(actor, Permission::ApprovalRead)?;
            serde_json::to_value(build_template_views(state, actor).await.map_err(|error| error.to_string())?)
                .map_err(|error| error.to_string())?
        }
        "get_approval_flow" => approval_flow(state, actor, arguments).await?,
        "list_policy_rules" => {
            require_permission(actor, Permission::PolicyRead)?;
            serde_json::to_value(build_effective_policy(actor).map_err(|error| error.to_string())?)
                .map_err(|error| error.to_string())?
        }
        "list_data_policies" => data_policies(state, actor, arguments).await?,
        _ => return Err(format!("UNKNOWN_GOVERNANCE_TOOL: {name}")),
    };
    serde_json::to_string(&value).map_err(|error| error.to_string())
}

async fn my_context(state: &WebState, actor: &Actor) -> Result<Value, String> {
    let user = state.app.storage.user_by_id(actor.id.clone()).await.map_err(|error| error.to_string())?;
    let snapshot = dbx_core::governance::assets::load_asset_snapshot(&state.app, &actor.id).await.unwrap_or_default();
    let connections: HashMap<String, String> = state
        .app
        .storage
        .load_connections()
        .await
        .map_err(|error| error.to_string())?
        .into_iter()
        .map(|connection| (connection.id, connection.name))
        .collect();
    let mut group_names: HashMap<String, String> = HashMap::new();
    for summary in state.app.storage.list_asset_group_summaries().await.unwrap_or_default() {
        group_names.insert(summary.group.id, summary.group.name);
    }
    let memberships: Vec<Value> = state
        .app
        .storage
        .all_asset_group_members()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|member| member.user_id == actor.id)
        .map(|member| {
            json!({
                "group_id": member.group_id,
                "group_name": group_names.get(&member.group_id).cloned(),
            })
        })
        .collect();
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let grants: Vec<Value> = snapshot
        .grants
        .iter()
        .map(|grant| {
            json!({
                "id": grant.id,
                "principal_type": grant.principal_type,
                "principal_id": grant.principal_id,
                "role_code": grant.role_code,
                "target_kind": grant.target_kind.as_str(),
                "connection_group_id": grant.connection_group_id,
                "connection_id": grant.connection_id,
                "connection_name": grant.connection_id.as_ref().and_then(|id| connections.get(id).cloned()),
                "database_name": grant.database_name,
                "schema_name": grant.schema_name,
                "table_name": grant.table_name,
                "name_pattern": grant.name_pattern,
                "expires_at": grant.expires_at,
                "expired": grant.expires_at.as_deref().is_some_and(|expires| expires <= now.as_str()),
                "reason": grant.reason,
            })
        })
        .collect();
    let mut effective_permissions = permissions_for_roles(&actor.roles);
    effective_permissions.extend(permissions_for_roles(&actor.asset_roles));
    effective_permissions.sort();
    effective_permissions.dedup();
    Ok(json!({
        "user": {
            "id": actor.id,
            "display_name": user.as_ref().map(|user| user.display_name.clone()).unwrap_or_else(|| actor.display_name.clone()),
            "email": user.as_ref().map(|user| user.email.clone()),
        },
        "global_roles": actor.roles,
        "asset_roles": actor.asset_roles,
        "global_permissions": permissions_for_roles(&actor.roles),
        "asset_role_permissions": permissions_for_roles(&actor.asset_roles),
        "effective_permissions": effective_permissions,
        "asset_groups": memberships,
        "asset_grants": grants,
        "note": "Asset role permissions apply only inside the listed grants. Approval actions remain human-only.",
    }))
}

async fn my_approvals(state: &WebState, actor: &Actor, arguments: &Value) -> Result<Value, String> {
    let limit = arg_limit(arguments, 20, 50);
    let tasks = build_my_tasks(state, actor, limit).await.map_err(|error| error.to_string())?;
    let scope = arg_str(arguments, "scope").unwrap_or("mine");
    let (mine, pending) = match scope {
        "pending" => (Vec::new(), tasks.pending_approvals),
        "all" => (tasks.approvals, tasks.pending_approvals),
        _ => (tasks.approvals, Vec::new()),
    };
    Ok(json!({ "scope": scope, "approvals": mine, "pending_approvals": pending }))
}

async fn my_approval(state: &WebState, actor: &Actor, arguments: &Value) -> Result<Value, String> {
    let id = arg_str(arguments, "approval_id").ok_or("MISSING_ARGUMENT: approval_id")?;
    let tasks = build_my_tasks(state, actor, 50).await.map_err(|error| error.to_string())?;
    let found = tasks.approvals.into_iter().chain(tasks.pending_approvals).find(|approval| approval.id == id);
    match found {
        Some(approval) => serde_json::to_value(approval).map_err(|error| error.to_string()),
        None => Err(format!("APPROVAL_NOT_VISIBLE: {id} is not one of the signed-in user's own or pending approvals")),
    }
}

async fn my_access_requests(state: &WebState, actor: &Actor, arguments: &Value) -> Result<Value, String> {
    let limit = arg_limit(arguments, 20, 50);
    let tasks = build_my_tasks(state, actor, limit).await.map_err(|error| error.to_string())?;
    let scope = arg_str(arguments, "scope").unwrap_or("mine");
    let (mine, pending) = match scope {
        "pending" => (Vec::new(), tasks.pending_access_requests),
        "all" => (tasks.access_requests, tasks.pending_access_requests),
        _ => (tasks.access_requests, Vec::new()),
    };
    Ok(json!({ "scope": scope, "access_requests": mine, "pending_access_requests": pending }))
}

async fn simulate_policy(state: &WebState, actor: &Actor, arguments: &Value) -> Result<Value, String> {
    require_permission(actor, Permission::QueryRead)?;
    let connection_id = arg_str(arguments, "connection_id").ok_or("MISSING_ARGUMENT: connection_id")?;
    let database = arg_str(arguments, "database").ok_or("MISSING_ARGUMENT: database")?;
    let sql = arg_str(arguments, "sql").ok_or("MISSING_ARGUMENT: sql")?;
    if dbx_core::governance::assets::actor_is_managed(actor) {
        let snapshot = dbx_core::governance::assets::load_asset_snapshot(&state.app, &actor.id)
            .await
            .map_err(|error| error.to_string())?;
        if !snapshot.can_navigate_connection(connection_id) {
            return Err("ASSET_ACCESS_DENIED: the connection is outside the user's asset grants".to_string());
        }
    }
    let config = {
        let configs = state.app.configs.read().await;
        configs.get(connection_id).cloned()
    }
    .ok_or_else(|| format!("CONNECTION_NOT_OPEN: {connection_id}; open the connection first"))?;
    let production = dbx_core::production_safety::is_production_database(&config, database);
    let decision = dbx_core::governance::decide(connection_id, &config, database, config.db_type, sql);
    Ok(json!({
        "effect": decision.effect.as_str(),
        "approval_required": decision.effect == dbx_core::governance::PolicyEffect::RequireApproval,
        "rule_id": decision.rule_id,
        "reason": decision.reason,
        "matched": decision.matched.iter().map(|hit| json!({
            "rule_id": hit.rule_id,
            "effect": hit.effect.as_str(),
            "reason": hit.reason,
        })).collect::<Vec<_>>(),
        "production": production,
        "enforcement": dbx_core::governance::enforcement_enabled(),
        "policy_bundle_hash": decision.policy_bundle_hash,
    }))
}

async fn audit_events(state: &WebState, actor: &Actor, arguments: &Value) -> Result<Value, String> {
    require_permission(actor, Permission::AuditRead)?;
    let mut query: AuditEventsQuery =
        serde_json::from_value(arguments.clone()).map_err(|error| format!("INVALID_ARGUMENT: {error}"))?;
    query.limit = Some(arg_limit(arguments, 20, MAX_ROWS));
    let page = query_events_for_actor(state, actor, query).await.map_err(|error| error.to_string())?;
    let scope = if dbx_core::identity::can_view_all_audit(&actor.roles) { "all" } else { "self" };
    Ok(json!({ "scope": scope, "events": page.events, "next_cursor": page.next_cursor }))
}

async fn list_users(state: &WebState, actor: &Actor, arguments: &Value) -> Result<Value, String> {
    require_permission(actor, Permission::AdminUsers)?;
    let mut users = build_user_views(state, actor).await.map_err(|error| error.to_string())?;
    if let Some(query) = arg_str(arguments, "q") {
        let needle = query.to_ascii_lowercase();
        users.retain(|user| {
            user.email.to_ascii_lowercase().contains(&needle)
                || user.display_name.to_ascii_lowercase().contains(&needle)
        });
    }
    let limit = arg_limit(arguments, 200, 500);
    users.truncate(limit);
    serde_json::to_value(users).map_err(|error| error.to_string())
}

async fn list_asset_grants(state: &WebState, actor: &Actor, arguments: &Value) -> Result<Value, String> {
    require_permission(actor, Permission::AdminUsers)?;
    let include_expired = arguments.get("include_expired").and_then(Value::as_bool).unwrap_or(false);
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let user_names: HashMap<String, String> = state
        .app
        .storage
        .list_users()
        .await
        .map_err(|error| error.to_string())?
        .into_iter()
        .map(|user| (user.id, user.display_name))
        .collect();
    let group_names: HashMap<String, String> = state
        .app
        .storage
        .list_asset_group_summaries()
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|summary| (summary.group.id, summary.group.name))
        .collect();
    let connections: HashMap<String, String> = state
        .app
        .storage
        .load_connections()
        .await
        .map_err(|error| error.to_string())?
        .into_iter()
        .map(|connection| (connection.id, connection.name))
        .collect();
    let filter_user = arg_str(arguments, "user_id");
    let filter_connection = arg_str(arguments, "connection_id");
    let filter_role = arg_str(arguments, "role_code");
    // A user filter resolves through the snapshot so grants inherited from
    // access groups are included, matching the access-inventory endpoint.
    let mut grants = if let Some(user) = filter_user {
        dbx_core::governance::assets::load_asset_snapshot(&state.app, user)
            .await
            .map_err(|error| error.to_string())?
            .grants
    } else {
        state.app.storage.list_all_asset_grants().await.map_err(|error| error.to_string())?
    };
    grants.retain(|grant| {
        if filter_user.is_none()
            && !include_expired
            && grant.expires_at.as_deref().is_some_and(|expires| expires <= now.as_str())
        {
            return false;
        }
        if filter_connection.is_some_and(|connection| grant.connection_id.as_deref() != Some(connection)) {
            return false;
        }
        if filter_role.is_some_and(|role| grant.role_code != role) {
            return false;
        }
        true
    });
    grants.truncate(arg_limit(arguments, 200, 200));
    let views: Vec<Value> = grants
        .iter()
        .map(|grant| {
            json!({
                "id": grant.id,
                "principal_type": grant.principal_type,
                "principal_id": grant.principal_id,
                "principal_name": if grant.principal_type == "group" {
                    group_names.get(&grant.principal_id).cloned()
                } else {
                    user_names.get(&grant.principal_id).cloned()
                },
                "role_code": grant.role_code,
                "target_kind": grant.target_kind.as_str(),
                "connection_group_id": grant.connection_group_id,
                "connection_id": grant.connection_id,
                "connection_name": grant.connection_id.as_ref().and_then(|id| connections.get(id).cloned()),
                "database_name": grant.database_name,
                "schema_name": grant.schema_name,
                "table_name": grant.table_name,
                "name_pattern": grant.name_pattern,
                "expires_at": grant.expires_at,
                "reason": grant.reason,
            })
        })
        .collect();
    Ok(json!({ "grants": views }))
}

async fn user_permissions(state: &WebState, actor: &Actor, arguments: &Value) -> Result<Value, String> {
    let target_id = arg_str(arguments, "user_id").unwrap_or(&actor.id).to_string();
    if target_id != actor.id {
        require_permission(actor, Permission::AdminUsers)?;
    }
    let user = state
        .app
        .storage
        .user_by_id(target_id.clone())
        .await
        .map_err(|error| error.to_string())?
        .ok_or_else(|| format!("USER_NOT_FOUND: {target_id}"))?;
    let roles = state.app.storage.role_codes_for_user(target_id.clone()).await.unwrap_or_default();
    let asset_roles = state.app.storage.asset_role_codes_for_user(target_id.clone()).await.unwrap_or_default();
    let mut effective_permissions = permissions_for_roles(&roles);
    effective_permissions.extend(permissions_for_roles(&asset_roles));
    effective_permissions.sort();
    effective_permissions.dedup();
    let bindings: Vec<Value> = state
        .app
        .storage
        .bindings_for_user(target_id.clone())
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|binding| {
            json!({
                "role_code": binding.role_code,
                "scope_type": binding.scope_type,
                "scope_id": binding.scope_id,
            })
        })
        .collect();
    let snapshot = dbx_core::governance::assets::load_asset_snapshot(&state.app, &target_id).await.unwrap_or_default();
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let grants: Vec<Value> = snapshot
        .grants
        .iter()
        .filter(|grant| !grant.expires_at.as_deref().is_some_and(|expires| expires <= now.as_str()))
        .map(|grant| {
            json!({
                "id": grant.id,
                "principal_type": grant.principal_type,
                "principal_id": grant.principal_id,
                "role_code": grant.role_code,
                "target_kind": grant.target_kind.as_str(),
                "connection_group_id": grant.connection_group_id,
                "connection_id": grant.connection_id,
                "database_name": grant.database_name,
                "schema_name": grant.schema_name,
                "table_name": grant.table_name,
                "name_pattern": grant.name_pattern,
                "expires_at": grant.expires_at,
            })
        })
        .collect();
    Ok(json!({
        "user": {
            "id": user.id,
            "email": user.email,
            "display_name": user.display_name,
            "status": user.status,
        },
        "global_roles": roles,
        "asset_roles": asset_roles,
        "global_permissions": permissions_for_roles(
            &state.app.storage.role_codes_for_user(target_id.clone()).await.unwrap_or_default()
        ),
        "asset_role_permissions": permissions_for_roles(
            &state.app.storage.asset_role_codes_for_user(target_id.clone()).await.unwrap_or_default()
        ),
        "effective_permissions": effective_permissions,
        "bindings": bindings,
        "asset_grants": grants,
    }))
}

async fn approval_flow(state: &WebState, actor: &Actor, arguments: &Value) -> Result<Value, String> {
    require_permission(actor, Permission::ApprovalRead)?;
    let id = arg_str(arguments, "approval_id").ok_or("MISSING_ARGUMENT: approval_id")?;
    let detail = build_approval_detail(state, actor, id).await.map_err(|error| error.to_string())?;
    serde_json::to_value(detail).map_err(|error| error.to_string())
}

async fn data_policies(state: &WebState, actor: &Actor, arguments: &Value) -> Result<Value, String> {
    require_permission(actor, Permission::AdminUsers)?;
    let connection_id = arg_str(arguments, "connection_id").map(str::to_string);
    let policies = state.app.storage.list_data_policies(connection_id).await.map_err(|error| error.to_string())?;
    let views: Vec<crate::routes::data_policies::DataPolicyView> =
        policies.into_iter().map(crate::routes::data_policies::DataPolicyView::from).collect();
    serde_json::to_value(views).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dbx_core::audit::{Actor, ActorKind};

    fn actor(roles: &[&str]) -> Actor {
        Actor {
            id: "u1".to_string(),
            display_name: "User One".to_string(),
            kind: ActorKind::Human,
            roles: roles.iter().map(|role| role.to_string()).collect(),
            asset_roles: Vec::new(),
            tenant_id: None,
            session_id: None,
            auth_method: "password".to_string(),
        }
    }

    fn names(actor: &Actor) -> Vec<String> {
        tool_definitions(actor).into_iter().map(|tool| tool.name.to_string()).collect()
    }

    #[test]
    fn self_tools_need_no_governance_permission() {
        let tools = names(&actor(&[]));
        assert!(tools.contains(&"get_my_context".to_string()));
        assert!(tools.contains(&"list_my_approvals".to_string()));
        assert!(tools.contains(&"get_my_approval".to_string()));
        assert!(tools.contains(&"list_my_access_requests".to_string()));
        assert!(!tools.contains(&"query_audit_events".to_string()));
        assert!(!tools.contains(&"list_users".to_string()));
    }

    #[test]
    fn governance_tools_follow_existing_permissions() {
        let admin = names(&actor(&["admin"]));
        for expected in [
            "query_audit_events",
            "list_users",
            "list_roles",
            "list_asset_grants",
            "list_data_policies",
            "list_approval_templates",
            "get_approval_flow",
            "list_policy_rules",
            "simulate_policy",
        ] {
            assert!(admin.contains(&expected.to_string()), "missing {expected}");
        }
        let viewer = names(&actor(&["viewer"]));
        assert!(viewer.contains(&"simulate_policy".to_string()));
        assert!(!viewer.contains(&"list_users".to_string()));
        let auditor = names(&actor(&["auditor"]));
        assert!(auditor.contains(&"query_audit_events".to_string()));
        assert!(auditor.contains(&"get_approval_flow".to_string()));
        assert!(!auditor.contains(&"list_users".to_string()));
    }

    #[test]
    fn tools_are_read_only() {
        for definition in tool_definitions(&actor(&["admin"])) {
            assert!(definition.read_only);
            assert!(definition.parallel_ok);
        }
    }
}
