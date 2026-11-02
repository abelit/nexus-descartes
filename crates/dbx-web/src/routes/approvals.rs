//! Approval templates, requests, steps, and one-time execution tokens.
//!
//! A request walks a template's steps in order. `any` steps need one approval,
//! `all` steps are countersigned by every approver snapshotted at request
//! creation, and a rejection closes the request immediately. The requester is
//! always excluded from their own approval.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use axum::extract::{Path, Query as AxumQuery, State};
use axum::http::HeaderMap;
use axum::Extension;
use axum::Json;
use dbx_core::audit::Actor;
use dbx_core::governance::approval::{
    default_approval_step, materialize_approval_steps, new_approval_token, parse_steps_document, request_hash,
    statements_digest, ApprovalBinding, ApprovalDecisionOutcome, ApprovalRequest, ApprovalStatus, ApprovalStep,
    ApprovalStepDecision, ApprovalTemplate, ApprovalToken, ApprovalVote,
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
pub struct ApprovalStepView {
    pub id: String,
    pub step_no: i64,
    pub mode: String,
    pub status: String,
    pub approver_roles: Vec<String>,
    pub approver_users: Vec<String>,
    pub required_user_ids: Vec<String>,
    pub decided_by: Option<String>,
    pub decided_at_ms: Option<i64>,
    pub comment: String,
}

impl From<&ApprovalStep> for ApprovalStepView {
    fn from(step: &ApprovalStep) -> Self {
        Self {
            id: step.id.clone(),
            step_no: step.step_no,
            mode: step.mode.as_str().to_string(),
            status: step.status.as_str().to_string(),
            approver_roles: step.approver_roles.clone(),
            approver_users: step.approver_users.clone(),
            required_user_ids: step.required_user_ids.clone(),
            decided_by: step.decided_by.clone(),
            decided_at_ms: step.decided_at_ms,
            comment: step.comment.clone(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ApprovalDecisionView {
    pub step_no: i64,
    pub actor_id: String,
    pub decision: String,
    pub comment: String,
    pub created_at_ms: i64,
}

impl From<&ApprovalStepDecision> for ApprovalDecisionView {
    fn from(decision: &ApprovalStepDecision) -> Self {
        Self {
            step_no: decision.step_no,
            actor_id: decision.actor_id.clone(),
            decision: decision.decision.as_str().to_string(),
            comment: decision.comment.clone(),
            created_at_ms: decision.created_at_ms,
        }
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
    pub template_id: String,
    pub current_step_no: i64,
    pub step_count: i64,
    pub steps: Vec<ApprovalStepView>,
    pub created_at_ms: i64,
    pub expires_at_ms: Option<i64>,
}

impl ApprovalView {
    fn from_parts(request: ApprovalRequest, steps: Vec<ApprovalStep>) -> Self {
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
            template_id: request.template_id,
            current_step_no: request.current_step_no,
            step_count: request.step_count,
            steps: steps.iter().map(ApprovalStepView::from).collect(),
            created_at_ms: request.created_at_ms,
            expires_at_ms: request.expires_at_ms,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ApprovalDetailView {
    #[serde(flatten)]
    pub request: ApprovalView,
    pub decisions: Vec<ApprovalDecisionView>,
}

#[derive(Debug, Deserialize)]
pub struct CreateApprovalRequest {
    pub connection_id: String,
    #[serde(default)]
    pub database: String,
    #[serde(default)]
    pub schema_name: Option<String>,
    pub sql: String,
    /// Optional pre-split statements for a batch; when absent the SQL is a
    /// single statement.
    #[serde(default)]
    pub statements: Option<Vec<String>>,
    #[serde(default)]
    pub justification: String,
    /// Overrides the template resolved from the connection scope.
    #[serde(default)]
    pub template_id: Option<String>,
}

fn template_document(
    steps: &serde_json::Value,
) -> Result<Vec<dbx_core::governance::approval::ApprovalStepSpec>, AppError> {
    parse_steps_document(&steps.to_string()).map_err(AppError::bad_request)
}

async fn role_members(
    state: &WebState,
    specs: &[dbx_core::governance::approval::ApprovalStepSpec],
) -> Result<HashMap<String, Vec<String>>, AppError> {
    let roles: BTreeSet<String> = specs
        .iter()
        .flat_map(|spec| spec.roles.iter())
        .map(|role| role.trim().to_string())
        .filter(|role| !role.is_empty())
        .collect();
    let mut members = HashMap::new();
    for role in roles {
        let users = state.app.storage.active_user_ids_for_role(role.clone()).await.map_err(AppError::from)?;
        members.insert(role, users);
    }
    Ok(members)
}

async fn validate_named_users(
    state: &WebState,
    specs: &[dbx_core::governance::approval::ApprovalStepSpec],
) -> Result<(), AppError> {
    for spec in specs {
        for user_id in &spec.users {
            let user_id = user_id.trim();
            if user_id.is_empty() {
                continue;
            }
            let user = state.app.storage.user_by_id(user_id.to_string()).await.map_err(AppError::from)?;
            match user {
                Some(user) if user.status == "active" => {}
                _ => {
                    return Err(AppError::bad_request(format!(
                        "APPROVAL_TEMPLATE_INVALID: unknown or inactive user {user_id}"
                    )))
                }
            }
        }
    }
    Ok(())
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

    let statements = match body.statements.clone().filter(|statements| !statements.is_empty()) {
        Some(statements) => statements,
        None => vec![body.sql.clone()],
    };
    let digest = statements_digest(&statements);
    let mut rule_ids: Vec<String> = Vec::new();
    let mut policy_bundle_hash: Option<String> = None;
    for sql in &statements {
        let decision = dbx_core::governance::decide(&body.connection_id, &config, &body.database, config.db_type, sql);
        policy_bundle_hash = Some(decision.policy_bundle_hash.clone());
        rule_ids.extend(
            decision
                .matched
                .iter()
                .filter(|hit| hit.effect == dbx_core::governance::PolicyEffect::RequireApproval)
                .map(|hit| hit.rule_id.clone()),
        );
    }
    rule_ids.sort();
    rule_ids.dedup();
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
        policy_bundle_hash: policy_bundle_hash.as_deref(),
        rule_ids: &rule_ids,
    });

    let template = match body.template_id.as_deref().map(str::trim).filter(|id| !id.is_empty()) {
        Some(template_id) => {
            let template = state
                .app
                .storage
                .approval_template_by_id(template_id.to_string())
                .await
                .map_err(AppError::from)?
                .ok_or_else(|| AppError::not_found("approval template not found"))?;
            if !template.enabled {
                return Err(AppError::bad_request("APPROVAL_TEMPLATE_DISABLED: the template is disabled"));
            }
            Some(template)
        }
        None => {
            state.app.storage.resolve_approval_template(body.connection_id.clone()).await.map_err(AppError::from)?
        }
    };

    let id = uuid::Uuid::new_v4().to_string();
    let steps = match &template {
        Some(template) => {
            validate_named_users(&state, &template.steps).await?;
            let members = role_members(&state, &template.steps).await?;
            materialize_approval_steps(&id, &actor.id, &template.steps, &members).map_err(AppError::bad_request)?
        }
        None => vec![default_approval_step(&id)],
    };
    let step_count = i64::try_from(steps.len()).unwrap_or(i64::MAX);

    let now = chrono::Utc::now().timestamp_millis();
    let request = ApprovalRequest {
        id,
        request_type: "sql".to_string(),
        status: ApprovalStatus::Pending,
        requester_id: actor.id.clone(),
        connection_id: body.connection_id,
        database: body.database,
        schema_name: body.schema_name,
        sql_text: statements.join(";\n"),
        sql_digest: digest,
        statement_count: i64::try_from(statements.len()).unwrap_or(i64::MAX),
        risk_level: None,
        rule_ids,
        policy_bundle_hash,
        justification: body.justification,
        request_hash: hash,
        template_id: template.map(|template| template.id).unwrap_or_default(),
        current_step_no: 1,
        step_count,
        expires_at_ms: None,
        created_at_ms: now,
        updated_at_ms: now,
        executed_at_ms: None,
    };
    state
        .app
        .storage
        .create_approval_request_with_steps(request.clone(), steps.clone())
        .await
        .map_err(AppError::from)?;
    notify_approval("approval.created", &request);
    Ok(Json(ApprovalView::from_parts(request, steps)))
}

#[derive(Debug, Default, Deserialize)]
pub struct ListApprovalsQuery {
    #[serde(default)]
    pub mine: Option<bool>,
    #[serde(default)]
    pub status: Option<String>,
    /// Only requests whose current step this actor may decide.
    #[serde(default)]
    pub assigned: Option<bool>,
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
    let ids: Vec<String> = requests.iter().map(|request| request.id.clone()).collect();
    let steps = state.app.storage.approval_steps_for_requests(ids).await.map_err(AppError::from)?;
    let mut by_request: HashMap<String, Vec<ApprovalStep>> = HashMap::new();
    for step in steps {
        by_request.entry(step.request_id.clone()).or_default().push(step);
    }
    let assigned_only = query.assigned.unwrap_or(false);
    let mut views = Vec::with_capacity(requests.len());
    for request in requests {
        let steps = by_request.remove(&request.id).unwrap_or_default();
        if assigned_only {
            let current = steps.iter().find(|step| step.step_no == request.current_step_no);
            let actionable = current.is_some_and(|step| {
                request.status == ApprovalStatus::Pending
                    && request.requester_id != actor.id
                    && step.allows(&actor.id, &actor.roles)
            });
            if !actionable {
                continue;
            }
        }
        views.push(ApprovalView::from_parts(request, steps));
    }
    Ok(Json(views))
}

pub async fn get_request(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Path(request_id): Path<String>,
) -> Result<Json<ApprovalDetailView>, AppError> {
    require(&actor, Permission::ApprovalRead)?;
    let request = load_request(&state, &request_id).await?;
    let steps = state.app.storage.approval_steps_for_request(request.id.clone()).await.map_err(AppError::from)?;
    // The requester, an administrator, and anyone who may decide a step can
    // see the full timeline.
    let can_view = request.requester_id == actor.id
        || dbx_core::identity::has_permission(&actor.roles, Permission::AdminSettings)
        || steps.iter().any(|step| step.allows(&actor.id, &actor.roles));
    if !can_view {
        return Err(AppError::forbidden("APPROVAL_FORBIDDEN: this request is not assigned to you"));
    }
    let decisions =
        state.app.storage.approval_step_decisions_for_request(request.id.clone()).await.map_err(AppError::from)?;
    Ok(Json(ApprovalDetailView {
        request: ApprovalView::from_parts(request, steps),
        decisions: decisions.iter().map(ApprovalDecisionView::from).collect(),
    }))
}

async fn load_request(state: &WebState, request_id: &str) -> Result<ApprovalRequest, AppError> {
    state
        .app
        .storage
        .approval_request_by_id(request_id.to_string())
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("approval request not found"))
}

#[derive(Debug, Deserialize)]
pub struct DecisionRequest {
    #[serde(default)]
    pub comment: String,
}

fn decision_error(error: String) -> AppError {
    match error.as_str() {
        "APPROVAL_NOT_FOUND" => AppError::not_found("approval request not found"),
        "APPROVAL_NOT_PENDING" => AppError::conflict("APPROVAL_NOT_PENDING: this request was already decided"),
        "APPROVAL_EXPIRED" => AppError::conflict("APPROVAL_EXPIRED: this request has expired"),
        "APPROVAL_NOT_APPROVER" => {
            AppError::forbidden("APPROVAL_NOT_APPROVER: you are not an approver for the current step")
        }
        "APPROVAL_ALREADY_DECIDED" => AppError::conflict("APPROVAL_ALREADY_DECIDED: you already decided this step"),
        "APPROVAL_STEP_MISSING" => AppError::conflict("APPROVAL_STEP_MISSING: the request has no open step"),
        _ => AppError::from(error),
    }
}

async fn decide(
    state: &WebState,
    actor: &Actor,
    request_id: &str,
    vote: ApprovalVote,
    comment: &str,
) -> Result<ApprovalView, AppError> {
    require(actor, Permission::ApprovalAct)?;
    let request = load_request(state, request_id).await?;
    if request.requester_id == actor.id {
        return Err(AppError::forbidden("APPROVAL_SELF_DECISION: the requester cannot decide their own request"));
    }
    let now = chrono::Utc::now().timestamp_millis();
    let outcome: ApprovalDecisionOutcome = state
        .app
        .storage
        .decide_approval_step(request.id.clone(), actor.id.clone(), actor.roles.clone(), vote, comment.to_string(), now)
        .await
        .map_err(decision_error)?;

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
    let decision = if vote == ApprovalVote::Approve {
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
            "vote": vote.as_str(),
            "status": outcome.request_status.as_str(),
            "step_no": outcome.step_no,
            "step_status": outcome.step_status.as_str(),
            "step_completed": outcome.step_completed,
            "comment": comment,
            "rule_ids": request.rule_ids,
        })
        .to_string(),
    );
    state.app.record_audit(event);

    let refreshed = load_request(state, request_id).await?;
    let steps = state.app.storage.approval_steps_for_request(refreshed.id.clone()).await.map_err(AppError::from)?;
    notify_approval(
        match (outcome.request_status, outcome.step_completed) {
            (ApprovalStatus::Rejected, _) => "approval.rejected",
            (ApprovalStatus::Approved, _) => "approval.approved",
            (_, true) => "approval.step_approved",
            _ => "approval.step_pending",
        },
        &refreshed,
    );
    Ok(ApprovalView::from_parts(refreshed, steps))
}

/// Fire-and-forget fan-out over the configured webhook and chat bots. The SQL
/// text is intentionally not sent.
fn notify_approval(event: &str, request: &ApprovalRequest) {
    let notifier = dbx_core::governance::notification::ApprovalNotifier::from_env();
    if !notifier.is_configured() {
        return;
    }
    let payload = dbx_core::governance::notification::approval_payload(
        &request.id,
        request.status.as_str(),
        &request.requester_id,
        &request.connection_id,
        &request.database,
        &request.rule_ids,
        request.statement_count,
    );
    let event = event.to_string();
    tokio::spawn(async move {
        for error in notifier.send(&event, &payload).await {
            log::warn!("approval notification failed: {error}");
        }
    });
}

pub async fn approve(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Path(request_id): Path<String>,
    Json(body): Json<DecisionRequest>,
) -> Result<Json<ApprovalView>, AppError> {
    decide(&state, &actor, &request_id, ApprovalVote::Approve, &body.comment).await.map(Json)
}

pub async fn reject(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Path(request_id): Path<String>,
    Json(body): Json<DecisionRequest>,
) -> Result<Json<ApprovalView>, AppError> {
    decide(&state, &actor, &request_id, ApprovalVote::Reject, &body.comment).await.map(Json)
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
    let request = load_request(&state, &request_id).await?;
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

#[derive(Debug, Serialize)]
pub struct TemplateView {
    pub id: String,
    pub name: String,
    pub scope_type: String,
    pub scope_id: String,
    pub steps: Vec<dbx_core::governance::approval::ApprovalStepSpec>,
    pub sla_secs: Option<i64>,
    pub enabled: bool,
    pub created_by: String,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

impl From<ApprovalTemplate> for TemplateView {
    fn from(template: ApprovalTemplate) -> Self {
        Self {
            id: template.id,
            name: template.name,
            scope_type: template.scope_type,
            scope_id: template.scope_id,
            steps: template.steps,
            sla_secs: template.sla_secs,
            enabled: template.enabled,
            created_by: template.created_by,
            created_at_ms: template.created_at_ms,
            updated_at_ms: template.updated_at_ms,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct TemplateRequest {
    pub name: String,
    #[serde(default)]
    pub scope_type: Option<String>,
    #[serde(default)]
    pub scope_id: Option<String>,
    #[serde(default)]
    pub sla_secs: Option<i64>,
    #[serde(default)]
    pub enabled: Option<bool>,
    /// Either a bare `[{...}]` step array or `{"steps": [...]}`.
    pub steps: serde_json::Value,
}

fn template_scope(scope_type: Option<&str>, scope_id: Option<&str>) -> Result<(String, String), AppError> {
    let scope_type = scope_type.unwrap_or("global").trim().to_string();
    let scope_id = scope_id.unwrap_or("").trim().to_string();
    match scope_type.as_str() {
        "global" if scope_id.is_empty() => Ok((scope_type, scope_id)),
        "global" => Err(AppError::bad_request("APPROVAL_TEMPLATE_INVALID: a global template must not set a scope id")),
        "connection" if !scope_id.is_empty() => Ok((scope_type, scope_id)),
        "connection" => {
            Err(AppError::bad_request("APPROVAL_TEMPLATE_INVALID: a connection template needs a connection id"))
        }
        _ => Err(AppError::bad_request("APPROVAL_TEMPLATE_INVALID: scope_type must be `global` or `connection`")),
    }
}

pub async fn list_templates(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
) -> Result<Json<Vec<TemplateView>>, AppError> {
    require(&actor, Permission::ApprovalRead)?;
    let templates = state.app.storage.list_approval_templates().await.map_err(AppError::from)?;
    Ok(Json(templates.into_iter().map(TemplateView::from).collect()))
}

pub async fn create_template(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Json(body): Json<TemplateRequest>,
) -> Result<Json<TemplateView>, AppError> {
    require(&actor, Permission::PolicyPublish)?;
    if body.name.trim().is_empty() {
        return Err(AppError::bad_request("APPROVAL_TEMPLATE_INVALID: name is required"));
    }
    let steps = template_document(&body.steps)?;
    let (scope_type, scope_id) = template_scope(body.scope_type.as_deref(), body.scope_id.as_deref())?;
    let now = chrono::Utc::now().timestamp_millis();
    let template = ApprovalTemplate {
        id: uuid::Uuid::new_v4().to_string(),
        name: body.name.trim().to_string(),
        scope_type,
        scope_id,
        steps,
        sla_secs: body.sla_secs,
        enabled: body.enabled.unwrap_or(true),
        created_by: actor.id.clone(),
        created_at_ms: now,
        updated_at_ms: now,
    };
    state.app.storage.create_approval_template(template.clone()).await.map_err(AppError::from)?;
    Ok(Json(TemplateView::from(template)))
}

pub async fn update_template(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Path(template_id): Path<String>,
    Json(body): Json<TemplateRequest>,
) -> Result<Json<TemplateView>, AppError> {
    require(&actor, Permission::PolicyPublish)?;
    let existing = state
        .app
        .storage
        .approval_template_by_id(template_id.clone())
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("approval template not found"))?;
    if body.name.trim().is_empty() {
        return Err(AppError::bad_request("APPROVAL_TEMPLATE_INVALID: name is required"));
    }
    let steps = template_document(&body.steps)?;
    let (scope_type, scope_id) = template_scope(body.scope_type.as_deref(), body.scope_id.as_deref())?;
    let template = ApprovalTemplate {
        id: existing.id,
        name: body.name.trim().to_string(),
        scope_type,
        scope_id,
        steps,
        sla_secs: body.sla_secs,
        enabled: body.enabled.unwrap_or(true),
        created_by: existing.created_by,
        created_at_ms: existing.created_at_ms,
        updated_at_ms: chrono::Utc::now().timestamp_millis(),
    };
    if !state.app.storage.update_approval_template(template.clone()).await.map_err(AppError::from)? {
        return Err(AppError::not_found("approval template not found"));
    }
    Ok(Json(TemplateView::from(template)))
}

pub async fn delete_template(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Path(template_id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    require(&actor, Permission::PolicyPublish)?;
    if !state.app.storage.delete_approval_template(template_id).await.map_err(AppError::from)? {
        return Err(AppError::not_found("approval template not found"));
    }
    Ok(Json(serde_json::json!({ "ok": true })))
}
