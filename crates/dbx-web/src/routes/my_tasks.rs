//! Self-scoped task summaries for the task center.
//!
//! Any signed-in actor may call this endpoint. It returns two buckets:
//! requests the actor submitted (never requiring `approval:read`) and requests
//! the actor can actually decide right now (SQL approval steps whose snapshot
//! includes them and where they have not voted, plus access requests whose
//! `admin:users` approver covers the requested role and target).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::Extension;
use axum::Json;
use dbx_core::audit::Actor;
use dbx_core::governance::approval::ApprovalStep;
use dbx_core::governance::assets::{load_asset_snapshot, AccessRequest, AccessRequestStatus, AssetGrant};
use dbx_core::identity::{has_permission, BuiltinRole, Permission};
use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::routes::users::snapshot_covers_access_request;
use crate::state::WebState;

#[derive(Debug, Default, Deserialize)]
pub struct MyTasksQuery {
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct MyTasksView {
    /// Requests the actor submitted.
    pub approvals: Vec<MyApprovalTaskView>,
    pub access_requests: Vec<MyAccessRequestTaskView>,
    /// Pending SQL approvals the actor can decide now.
    pub pending_approvals: Vec<MyApprovalTaskView>,
    /// Pending access requests the actor can decide now.
    pub pending_access_requests: Vec<MyAccessRequestTaskView>,
    pub generated_at_ms: i64,
}

#[derive(Debug, Serialize)]
pub struct MyApprovalTaskView {
    pub id: String,
    pub sql: String,
    pub requester_id: String,
    pub requester_name: String,
    pub connection_id: String,
    pub connection_name: Option<String>,
    pub database: String,
    pub schema_name: Option<String>,
    pub status: String,
    pub step_count: i64,
    pub current_step_no: i64,
    /// Users who can decide the current step (empty for terminal requests).
    pub current_approver_names: Vec<String>,
    pub execution_mode: String,
    pub execution_error: Option<String>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub executed_at_ms: Option<i64>,
    pub expires_at_ms: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct MyAccessRequestTaskView {
    pub id: String,
    pub requester_id: String,
    pub requester_name: String,
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
    pub status: String,
    /// Eligible approvers while the request is pending; empty otherwise.
    pub current_approver_names: Vec<String>,
    pub duration_hours: i64,
    pub expires_at: String,
    pub created_at: String,
    pub updated_at: String,
    pub decided_at: Option<String>,
    pub decided_by_name: Option<String>,
    pub decision_note: String,
    pub grant_id: Option<String>,
    /// active / expired / revoked / missing, mirroring the access-request view.
    pub grant_status: Option<String>,
    pub expired: bool,
}

struct ApproverCandidate {
    id: String,
    name: String,
    snapshot: dbx_core::governance::assets::AssetScopeSnapshot,
}

fn approval_step_approvers(step: Option<&ApprovalStep>, names: &HashMap<String, String>) -> Vec<String> {
    let Some(step) = step else {
        return Vec::new();
    };
    let mut approvers: Vec<String> =
        step.required_user_ids.iter().map(|id| names.get(id).cloned().unwrap_or_else(|| id.clone())).collect();
    approvers.sort();
    approvers.dedup();
    approvers
}

pub async fn my_tasks(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Query(query): Query<MyTasksQuery>,
) -> Result<Json<MyTasksView>, AppError> {
    let limit = query.limit.unwrap_or(20).clamp(1, 50);
    build_my_tasks(&state, &actor, limit).await.map(Json)
}

/// Shared by the HTTP handler and the AI governance tools so both surfaces use
/// the same self-scoping and pending-approver rules.
pub(crate) async fn build_my_tasks(state: &WebState, actor: &Actor, limit: usize) -> Result<MyTasksView, AppError> {
    let connection_names: HashMap<String, String> = state
        .app
        .storage
        .load_connections()
        .await
        .map_err(AppError::from)?
        .into_iter()
        .map(|connection| (connection.id, connection.name))
        .collect();
    let group_names: HashMap<String, String> = state
        .app
        .storage
        .list_connection_groups()
        .await
        .map_err(AppError::from)?
        .into_iter()
        .map(|group| (group.id, group.name))
        .collect();
    let users = state.app.storage.list_users().await.map_err(AppError::from)?;
    let grants_by_id: HashMap<String, AssetGrant> = state
        .app
        .storage
        .list_all_asset_grants()
        .await
        .map_err(AppError::from)?
        .into_iter()
        .map(|grant| (grant.id.clone(), grant))
        .collect();
    let user_names: HashMap<String, String> =
        users.iter().map(|user| (user.id.clone(), user.display_name.clone())).collect();
    let mut role_names: HashMap<String, String> =
        BuiltinRole::ALL.iter().map(|role| (role.code().to_string(), role.name().to_string())).collect();
    for role in state.app.storage.list_custom_roles().await.map_err(AppError::from)? {
        role_names.insert(role.code, role.name);
    }

    let own_approval_requests = state
        .app
        .storage
        .list_approval_requests(dbx_core::storage::ApprovalRequestQuery {
            requester_id: Some(actor.id.clone()),
            involved_actor_id: None,
            status: None,
            search: None,
            from_ms: None,
            to_ms: None,
            limit,
            offset: 0,
        })
        .await
        .map_err(AppError::from)?;
    let own_approval_ids: Vec<String> = own_approval_requests.iter().map(|request| request.id.clone()).collect();
    let own_steps = state.app.storage.approval_steps_for_requests(own_approval_ids).await.map_err(AppError::from)?;
    let own_access_requests = state
        .app
        .storage
        .list_access_requests(Some(actor.id.clone()), None, i64::try_from(limit).unwrap_or(20))
        .await
        .map_err(AppError::from)?;

    // Pending SQL approvals the actor can act on right now.
    let pending_requests = state
        .app
        .storage
        .list_approval_requests(dbx_core::storage::ApprovalRequestQuery {
            requester_id: None,
            involved_actor_id: None,
            status: Some("pending".to_string()),
            search: None,
            from_ms: None,
            to_ms: None,
            limit: 200,
            offset: 0,
        })
        .await
        .map_err(AppError::from)?;
    let pending_ids: Vec<String> = pending_requests.iter().map(|request| request.id.clone()).collect();
    let pending_steps =
        state.app.storage.approval_steps_for_requests(pending_ids.clone()).await.map_err(AppError::from)?;
    let decisions =
        state.app.storage.approval_step_decisions_for_requests(pending_ids).await.map_err(AppError::from)?;
    let voted: HashSet<(String, i64)> = decisions
        .iter()
        .filter(|decision| decision.actor_id == actor.id)
        .map(|decision| (decision.request_id.clone(), decision.step_no))
        .collect();

    // Eligible access-request approvers are resolved once for both the "my
    // requests" and "pending my approval" buckets.
    let any_pending_access = own_access_requests.iter().any(|request| request.status.as_str() == "pending")
        || has_permission(&actor.roles, Permission::AdminUsers);
    let mut approver_candidates: Vec<ApproverCandidate> = Vec::new();
    if any_pending_access {
        for user in users.iter().filter(|user| user.is_active()) {
            let roles = state.app.storage.role_codes_for_user(user.id.clone()).await.unwrap_or_default();
            if !has_permission(&roles, Permission::AdminUsers) {
                continue;
            }
            if let Ok(snapshot) = load_asset_snapshot(&state.app, &user.id).await {
                approver_candidates.push(ApproverCandidate {
                    id: user.id.clone(),
                    name: user.display_name.clone(),
                    snapshot,
                });
            }
        }
    }
    let access_approver_names = |request: &AccessRequest| -> Vec<String> {
        if request.status.as_str() != "pending" {
            return Vec::new();
        }
        let mut names: Vec<String> = approver_candidates
            .iter()
            .filter(|candidate| candidate.id != request.requester_id)
            .filter(|candidate| snapshot_covers_access_request(&candidate.snapshot, request))
            .map(|candidate| candidate.name.clone())
            .collect();
        names.sort();
        names.dedup();
        names
    };

    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let to_approval = |request: dbx_core::governance::approval::ApprovalRequest, steps: &[ApprovalStep]| {
        let current_step =
            steps.iter().find(|step| step.request_id == request.id && step.step_no == request.current_step_no);
        MyApprovalTaskView {
            current_approver_names: if request.status.as_str() == "pending" {
                approval_step_approvers(current_step, &user_names)
            } else {
                Vec::new()
            },
            requester_name: user_names
                .get(&request.requester_id)
                .cloned()
                .unwrap_or_else(|| request.requester_id.clone()),
            requester_id: request.requester_id,
            connection_name: connection_names.get(&request.connection_id).cloned(),
            id: request.id,
            sql: request.sql_text,
            connection_id: request.connection_id,
            database: request.database,
            schema_name: request.schema_name,
            status: request.status.as_str().to_string(),
            step_count: request.step_count,
            current_step_no: request.current_step_no,
            execution_mode: request.execution_mode.as_str().to_string(),
            execution_error: request.execution_error,
            created_at_ms: request.created_at_ms,
            updated_at_ms: request.updated_at_ms,
            executed_at_ms: request.executed_at_ms,
            expires_at_ms: request.expires_at_ms,
        }
    };
    let to_access = |request: AccessRequest| {
        let grant_status = if request.status == AccessRequestStatus::Revoked {
            Some("revoked".to_string())
        } else {
            request.grant_id.as_deref().map(|grant_id| {
                match grants_by_id.get(grant_id) {
                    None => "missing",
                    Some(grant) if grant.expires_at.as_deref().is_some_and(|expires| expires <= now.as_str()) => {
                        "expired"
                    }
                    Some(_) => "active",
                }
                .to_string()
            })
        };
        MyAccessRequestTaskView {
            current_approver_names: access_approver_names(&request),
            requester_name: user_names
                .get(&request.requester_id)
                .cloned()
                .unwrap_or_else(|| request.requester_id.clone()),
            requester_id: request.requester_id,
            role_name: role_names.get(&request.role_code).cloned().unwrap_or_else(|| request.role_code.clone()),
            role_code: request.role_code,
            target_kind: request.target_kind.as_str().to_string(),
            connection_name: request.connection_id.as_ref().and_then(|id| connection_names.get(id).cloned()),
            group_name: request.connection_group_id.as_ref().and_then(|id| group_names.get(id).cloned()),
            connection_group_id: request.connection_group_id,
            connection_id: request.connection_id,
            database_name: request.database_name,
            schema_name: request.schema_name,
            table_name: request.table_name,
            name_pattern: request.name_pattern,
            status: request.status.as_str().to_string(),
            duration_hours: request.duration_hours,
            expired: request.expires_at <= now,
            expires_at: request.expires_at,
            created_at: request.created_at,
            updated_at: request.updated_at,
            decided_by_name: request.decided_by.as_ref().and_then(|id| user_names.get(id).cloned()),
            decided_at: request.decided_at,
            decision_note: request.decision_note,
            grant_id: request.grant_id,
            grant_status,
            id: request.id,
        }
    };

    let approvals: Vec<MyApprovalTaskView> =
        own_approval_requests.into_iter().map(|request| to_approval(request, &own_steps)).collect();
    let access_requests: Vec<MyAccessRequestTaskView> = own_access_requests.into_iter().map(to_access).collect();

    let mut pending_approvals = Vec::new();
    for request in pending_requests {
        if request.requester_id == actor.id || pending_approvals.len() >= limit {
            continue;
        }
        let Some(step) =
            pending_steps.iter().find(|step| step.request_id == request.id && step.step_no == request.current_step_no)
        else {
            continue;
        };
        if !step.allows(&actor.id, &actor.roles) {
            continue;
        }
        if voted.contains(&(request.id.clone(), request.current_step_no)) {
            continue;
        }
        pending_approvals.push(to_approval(request, &pending_steps));
    }

    // Pending access requests this actor can approve. security_admin-style
    // admins without data permissions do not qualify.
    let mut pending_access_requests = Vec::new();
    if has_permission(&actor.roles, Permission::AdminUsers) {
        if let Ok(snapshot) = load_asset_snapshot(&state.app, &actor.id).await {
            let pending = state
                .app
                .storage
                .list_access_requests(None, Some("pending".to_string()), 200)
                .await
                .map_err(AppError::from)?;
            for request in pending {
                if request.requester_id == actor.id || pending_access_requests.len() >= limit {
                    continue;
                }
                if snapshot_covers_access_request(&snapshot, &request) {
                    pending_access_requests.push(to_access(request));
                }
            }
        }
    }

    Ok(MyTasksView {
        approvals,
        access_requests,
        pending_approvals,
        pending_access_requests,
        generated_at_ms: chrono::Utc::now().timestamp_millis(),
    })
}
