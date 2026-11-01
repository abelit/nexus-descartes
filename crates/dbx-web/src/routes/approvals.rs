//! Approval requests and one-time execution tokens.

use std::sync::Arc;

use axum::extract::{Path, Query as AxumQuery, State};
use axum::http::HeaderMap;
use axum::Extension;
use axum::Json;
use dbx_core::audit::Actor;
use dbx_core::governance::approval::{
    new_approval_token, request_hash, statements_digest, ApprovalBinding, ApprovalRequest, ApprovalStatus,
    ApprovalToken,
};
use dbx_core::identity::Permission;
use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::state::WebState;

const TOKEN_TTL_MS: i64 = 5 * 60 * 1000;

fn require(actor: &Actor, permission: Permission) -> Result<(), AppError> {
    if dbx_core::identity::has_permission(&actor.roles, permission) {
        Ok(())
    } else {
        Err(AppError::forbidden(format!("PERMISSION_DENIED: {}", permission.as_str())))
    }
}

#[derive(Debug, Serialize)]
pub struct ApprovalView {
    pub id: String,
    pub request_type: String,
    pub status: String,
    pub requester_id: String,
    pub connection_id: String,
    pub database: String,
    pub schema_name: Option<String>,
    pub sql_text: String,
    pub statement_count: i64,
    pub risk_level: Option<String>,
    pub rule_ids: Vec<String>,
    pub justification: String,
    pub created_at_ms: i64,
    pub expires_at_ms: Option<i64>,
}

impl From<ApprovalRequest> for ApprovalView {
    fn from(request: ApprovalRequest) -> Self {
        Self {
            id: request.id,
            request_type: request.request_type,
            status: request.status.as_str().to_string(),
            requester_id: request.requester_id,
            connection_id: request.connection_id,
            database: request.database,
            schema_name: request.schema_name,
            sql_text: request.sql_text,
            statement_count: request.statement_count,
            risk_level: request.risk_level,
            rule_ids: request.rule_ids,
            justification: request.justification,
            created_at_ms: request.created_at_ms,
            expires_at_ms: request.expires_at_ms,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateApprovalRequest {
    pub connection_id: String,
    #[serde(default)]
    pub database: String,
    #[serde(default)]
    pub schema_name: Option<String>,
    pub sql: String,
    #[serde(default)]
    pub justification: String,
}

pub async fn create_request(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Json(body): Json<CreateApprovalRequest>,
) -> Result<Json<ApprovalView>, AppError> {
    // Asking for approval requires the permission the execution itself needs.
    require(&actor, Permission::QueryWrite)?;
    if body.sql.trim().is_empty() {
        return Err(AppError::bad_request("sql is required"));
    }
    let config = {
        let configs = state.app.configs.read().await;
        configs.get(&body.connection_id).cloned()
    }
    .ok_or_else(|| AppError::not_found("connection not found"))?;

    let statements = vec![body.sql.clone()];
    let digest = statements_digest(&statements);
    let decision =
        dbx_core::governance::decide(&body.connection_id, &config, &body.database, config.db_type, &body.sql);
    let rule_ids: Vec<String> = decision
        .matched
        .iter()
        .filter(|hit| hit.effect == dbx_core::governance::PolicyEffect::RequireApproval)
        .map(|hit| hit.rule_id.clone())
        .collect();
    if rule_ids.is_empty() {
        return Err(AppError::bad_request(
            "APPROVAL_NOT_REQUIRED: the rules do not require approval for this statement",
        ));
    }
    let config_hash = dbx_core::governance::approval::connection_config_hash(&config);
    let hash = request_hash(&ApprovalBinding {
        connection_id: &body.connection_id,
        connection_config_hash: &config_hash,
        database: &body.database,
        schema: body.schema_name.as_deref(),
        statements_digest: &digest,
        policy_bundle_hash: Some(&decision.policy_bundle_hash),
        rule_ids: &rule_ids,
    });

    let now = chrono::Utc::now().timestamp_millis();
    let request = ApprovalRequest {
        id: uuid::Uuid::new_v4().to_string(),
        request_type: "sql".to_string(),
        status: ApprovalStatus::Pending,
        requester_id: actor.id.clone(),
        connection_id: body.connection_id,
        database: body.database,
        schema_name: body.schema_name,
        sql_text: body.sql,
        sql_digest: digest,
        statement_count: 1,
        risk_level: None,
        rule_ids,
        policy_bundle_hash: Some(decision.policy_bundle_hash.clone()),
        justification: body.justification,
        request_hash: hash,
        expires_at_ms: None,
        created_at_ms: now,
        updated_at_ms: now,
        executed_at_ms: None,
    };
    state.app.storage.create_approval_request(request.clone()).await.map_err(AppError::from)?;
    Ok(Json(request.into()))
}

#[derive(Debug, Default, Deserialize)]
pub struct ListApprovalsQuery {
    #[serde(default)]
    pub mine: Option<bool>,
    #[serde(default)]
    pub status: Option<String>,
}

pub async fn list_requests(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    AxumQuery(query): AxumQuery<ListApprovalsQuery>,
) -> Result<Json<Vec<ApprovalView>>, AppError> {
    require(&actor, Permission::ApprovalRead)?;
    let requester = query.mine.unwrap_or(false).then(|| actor.id.clone());
    let status = query.status.filter(|value| ApprovalStatus::parse(value).is_some());
    let requests = state.app.storage.list_approval_requests(requester, status, 200).await.map_err(AppError::from)?;
    Ok(Json(requests.into_iter().map(ApprovalView::from).collect()))
}

#[derive(Debug, Deserialize)]
pub struct DecisionRequest {
    #[serde(default)]
    pub comment: String,
}

async fn decide(
    state: &WebState,
    actor: &Actor,
    request_id: &str,
    status: ApprovalStatus,
    comment: &str,
) -> Result<ApprovalView, AppError> {
    require(actor, Permission::ApprovalAct)?;
    let request = state
        .app
        .storage
        .approval_request_by_id(request_id.to_string())
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("approval request not found"))?;
    if request.requester_id == actor.id {
        return Err(AppError::forbidden("APPROVAL_SELF_DECISION: the requester cannot decide their own request"));
    }
    let now = chrono::Utc::now().timestamp_millis();
    let decided =
        state.app.storage.decide_approval_request(request.id.clone(), status, now).await.map_err(AppError::from)?;
    if !decided {
        return Err(AppError::conflict("APPROVAL_NOT_PENDING: this request was already decided"));
    }
    // The decision itself is an audited action; the comment is the approver's
    // stated reason and belongs to the record.
    let context = dbx_core::audit::current_audit_context().unwrap_or_else(|| dbx_core::audit::AuditContext {
        actor: actor.clone(),
        source: dbx_core::audit::AuditSource::Web,
        client_ip: None,
        user_agent: None,
        request_id: None,
        execution_id: None,
    });
    let decision = if status == ApprovalStatus::Approved {
        dbx_core::audit::AuditDecision::Allowed
    } else {
        dbx_core::audit::AuditDecision::Denied
    };
    let mut event = dbx_core::audit::AuditEventInsert::new(
        &context,
        dbx_core::audit::AuditOperation::Approval,
        decision,
        dbx_core::audit::AuditOutcome::Success,
    );
    event.resource_type = Some("approval".to_string());
    event.resource_id = Some(request.id.clone());
    event.details_json = Some(
        serde_json::json!({
            "approval_id": request.id,
            "status": status.as_str(),
            "comment": comment,
            "rule_ids": request.rule_ids,
        })
        .to_string(),
    );
    state.app.record_audit(event);

    let refreshed = state
        .app
        .storage
        .approval_request_by_id(request_id.to_string())
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("approval request not found"))?;
    Ok(refreshed.into())
}

pub async fn approve(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Path(request_id): Path<String>,
    Json(body): Json<DecisionRequest>,
) -> Result<Json<ApprovalView>, AppError> {
    decide(&state, &actor, &request_id, ApprovalStatus::Approved, &body.comment).await.map(Json)
}

pub async fn reject(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Path(request_id): Path<String>,
    Json(body): Json<DecisionRequest>,
) -> Result<Json<ApprovalView>, AppError> {
    decide(&state, &actor, &request_id, ApprovalStatus::Rejected, &body.comment).await.map(Json)
}

#[derive(Debug, Serialize)]
pub struct ExecuteTokenView {
    /// The raw token. Returned once; only its hash is stored.
    pub token: String,
    pub expires_at_ms: i64,
}

pub async fn issue_execute_token(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Path(request_id): Path<String>,
    _headers: HeaderMap,
) -> Result<Json<ExecuteTokenView>, AppError> {
    let request = state
        .app
        .storage
        .approval_request_by_id(request_id.clone())
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("approval request not found"))?;
    if request.requester_id != actor.id {
        return Err(AppError::forbidden("APPROVAL_TOKEN_FORBIDDEN: only the requester may obtain the token"));
    }
    if request.status != ApprovalStatus::Approved {
        return Err(AppError::conflict("APPROVAL_NOT_APPROVED: the request is not approved"));
    }
    let now = chrono::Utc::now().timestamp_millis();
    let expires_at_ms = now + TOKEN_TTL_MS;
    let (raw, hash) = new_approval_token();
    state
        .app
        .storage
        .create_approval_token(ApprovalToken {
            id: uuid::Uuid::new_v4().to_string(),
            request_id: request.id,
            token_hash: hash,
            actor_id: actor.id,
            request_hash: request.request_hash,
            expires_at_ms,
            consumed_at_ms: None,
        })
        .await
        .map_err(AppError::from)?;
    Ok(Json(ExecuteTokenView { token: raw, expires_at_ms }))
}
