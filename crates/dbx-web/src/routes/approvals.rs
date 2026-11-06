//! Approval templates, requests, steps, and one-time execution tokens.
//!
//! A request walks a template's steps in order. `any` steps need one approval,
//! `all` steps are countersigned by every approver snapshotted at request
//! creation, and a rejection closes the request immediately. The requester is
//! always excluded from their own approval.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;

use axum::extract::{Path, Query as AxumQuery, State};
use axum::http::HeaderMap;
use axum::Extension;
use axum::Json;
use dbx_core::audit::{
    Actor, ActorKind, AuditContext, AuditDecision, AuditEventInsert, AuditOperation, AuditOutcome, AuditSource,
};
use dbx_core::governance::approval::{
    default_approval_step, materialize_approval_steps, new_approval_token, parse_steps_document, request_hash,
    statements_digest, ApprovalBinding, ApprovalDecisionOutcome, ApprovalExecutionMode, ApprovalRequest,
    ApprovalStatus, ApprovalStep, ApprovalStepDecision, ApprovalTemplate, ApprovalToken, ApprovalVote,
};
use dbx_core::identity::Permission;
use dbx_core::models::connection::DatabaseType;
use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::state::WebState;

const TOKEN_TTL_MS: i64 = 5 * 60 * 1000;

/// Split a submitted script with the same dialect rules the executor uses.
/// Without this, a batch is stored as one statement: policy is checked against
/// the whole string, `statement_count` is wrong, and PostgreSQL rejects the
/// request at execution time with "cannot insert multiple commands into a
/// prepared statement". Callers that already pre-split a batch keep their list.
fn approval_statements(sql: &str, db_type: DatabaseType, provided: Option<Vec<String>>) -> Vec<String> {
    if let Some(statements) = provided.filter(|statements| !statements.is_empty()) {
        return statements;
    }
    let plan = dbx_core::query::query_execution_plan(sql, Some(db_type), false);
    let statements = plan
        .statements
        .into_iter()
        .map(|statement| statement.trim().to_string())
        .filter(|statement| !statement.is_empty())
        .collect::<Vec<_>>();
    if statements.is_empty() {
        vec![sql.to_string()]
    } else {
        statements
    }
}

fn require(actor: &Actor, permission: Permission) -> Result<(), AppError> {
    let global = dbx_core::identity::has_permission(&actor.roles, permission);
    let asset = permission.is_asset_scopeable() && dbx_core::identity::has_permission(&actor.asset_roles, permission);
    if global || asset {
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
    /// This viewer's vote on this step, if any. An `all` step stays `pending`
    /// after one approval, so the UI needs this to stop offering Approve to the
    /// approver who already voted.
    pub my_decision: Option<String>,
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
            my_decision: None,
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
    pub execution_mode: String,
    pub execution_error: Option<String>,
    pub executed_by: Option<String>,
    pub executed_at_ms: Option<i64>,
    pub steps: Vec<ApprovalStepView>,
    /// Display names for every user id referenced by this request, so the UI
    /// never has to show a bare UUID (and non-admin approvers cannot list
    /// users to resolve ids themselves).
    pub user_names: HashMap<String, String>,
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
            execution_mode: request.execution_mode.as_str().to_string(),
            execution_error: request.execution_error,
            executed_by: request.executed_by,
            executed_at_ms: request.executed_at_ms,
            steps: steps.iter().map(ApprovalStepView::from).collect(),
            user_names: HashMap::new(),
            created_at_ms: request.created_at_ms,
            expires_at_ms: request.expires_at_ms,
        }
    }
}

/// Resolve the display names of everyone referenced by `views` (plus any
/// decision actors in `extra_ids`). A failing lookup leaves ids in place rather
/// than failing the approval response.
async fn attach_approval_user_names(state: &WebState, views: &mut [ApprovalView], extra_ids: &[String]) {
    let mut wanted: HashSet<String> = extra_ids.iter().cloned().collect();
    for view in views.iter() {
        wanted.insert(view.requester_id.clone());
        if let Some(executed_by) = &view.executed_by {
            wanted.insert(executed_by.clone());
        }
        for step in &view.steps {
            wanted.extend(step.approver_users.iter().cloned());
            if let Some(decided_by) = &step.decided_by {
                wanted.insert(decided_by.clone());
            }
        }
    }
    if wanted.is_empty() {
        return;
    }
    let Ok(users) = state.app.storage.list_users().await else {
        return;
    };
    let names: HashMap<String, String> =
        users.into_iter().filter(|user| wanted.contains(&user.id)).map(|user| (user.id, user.display_name)).collect();
    for view in views.iter_mut() {
        view.user_names = names.clone();
    }
}

/// Mark the current viewer's own vote on each step. `all` steps need every
/// approver, so a step can remain `pending` after this actor has voted.
fn attach_my_decisions(views: &mut [ApprovalView], decisions: &[ApprovalStepDecision], actor_id: &str) {
    let by_step: HashMap<(String, i64), String> = decisions
        .iter()
        .filter(|decision| decision.actor_id == actor_id)
        .map(|decision| ((decision.request_id.clone(), decision.step_no), decision.decision.as_str().to_string()))
        .collect();
    for view in views.iter_mut() {
        let request_id = view.id.clone();
        for step in &mut view.steps {
            step.my_decision = by_step.get(&(request_id.clone(), step.step_no)).cloned();
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
    Ok(Json(create_request_for_actor(&state, &actor, body).await?))
}

/// Shared approval creation used by the HTTP handler and the AI
/// `request_approval` tool. Callers are responsible for feature/permission
/// gating; this performs the same validation as an HTTP request.
pub(crate) async fn create_request_for_actor(
    state: &Arc<WebState>,
    actor: &Actor,
    body: CreateApprovalRequest,
) -> Result<ApprovalView, AppError> {
    // Asking for approval requires the permission the execution itself needs.
    require(actor, Permission::QueryWrite)?;
    if body.sql.trim().is_empty() {
        return Err(AppError::bad_request("sql is required"));
    }
    let config = {
        let configs = state.app.configs.read().await;
        configs.get(&body.connection_id).cloned()
    }
    .ok_or_else(|| AppError::not_found("connection not found"))?;

    let statements = approval_statements(&body.sql, config.db_type, body.statements.clone());
    let digest = statements_digest(&statements);
    let mut rule_ids: Vec<String> = Vec::new();
    let mut policy_bundle_hash: Option<String> = None;
    let mut bound_template_ids: BTreeSet<String> = BTreeSet::new();
    for sql in &statements {
        let decision = dbx_core::governance::decide(&body.connection_id, &config, &body.database, config.db_type, sql);
        // Block is terminal: an approval cannot override it, and execution
        // checks it even when the batch is policy-approved. Refuse the whole
        // request at creation instead of queueing work that can never run.
        if decision.effect == dbx_core::governance::PolicyEffect::Block {
            return Err(AppError::forbidden(format!(
                "POLICY_DENIED: {} (rule {})",
                decision.reason,
                decision.rule_id.as_deref().unwrap_or("unknown")
            )));
        }
        policy_bundle_hash = Some(decision.policy_bundle_hash.clone());
        rule_ids.extend(
            decision
                .matched
                .iter()
                .filter(|hit| hit.effect == dbx_core::governance::PolicyEffect::RequireApproval)
                .map(|hit| hit.rule_id.clone()),
        );
        if let Some(template_id) = decision.approval_template_id.filter(|id| !id.trim().is_empty()) {
            bound_template_ids.insert(template_id);
        }
    }
    rule_ids.sort();
    rule_ids.dedup();
    if rule_ids.is_empty() {
        return Err(AppError::bad_request(
            "APPROVAL_NOT_REQUIRED: the rules do not require approval for this statement",
        ));
    }
    // Asking for approval still requires access to the target asset. DDL is
    // allowed when the role grants query:write, because the approval covers the
    // DDL capability.
    if let Err(error) = dbx_core::governance::authorize_connection_scope(
        &state.app,
        Some(&actor.id),
        &body.connection_id,
        Some(&body.database),
        body.schema_name.as_deref(),
        &statements,
        Some(config.db_type),
        true,
    )
    .await
    {
        return Err(AppError::forbidden(format!("ASSET_ACCESS_DENIED: {error}")));
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

    if bound_template_ids.len() > 1 {
        return Err(AppError::conflict(
            "APPROVAL_TEMPLATE_CONFLICT: the matched rules bind different approval templates",
        ));
    }
    let rule_template_id = bound_template_ids.into_iter().next();
    let explicit_template_id = body.template_id.as_deref().map(str::trim).filter(|id| !id.is_empty());
    let template = match explicit_template_id.or(rule_template_id.as_deref()) {
        Some(template_id) => {
            let template = state
                .app
                .storage
                .approval_template_by_id(template_id.to_string())
                .await
                .map_err(AppError::from)?
                .ok_or_else(|| {
                    AppError::bad_request(format!(
                        "APPROVAL_TEMPLATE_MISSING: approval template {template_id} not found"
                    ))
                })?;
            if !template.enabled {
                return Err(AppError::bad_request("APPROVAL_TEMPLATE_DISABLED: the template is disabled"));
            }
            if template.scope_type == "connection" && template.scope_id != body.connection_id {
                return Err(AppError::bad_request(
                    "APPROVAL_TEMPLATE_SCOPE_MISMATCH: the template is scoped to another connection",
                ));
            }
            Some(template)
        }
        None => {
            state.app.storage.resolve_approval_template(body.connection_id.clone()).await.map_err(AppError::from)?
        }
    };

    // The template owns the post-approval execution mode; requesters cannot
    // override it. Templates without a mode keep the server default.
    let execution_mode = template
        .as_ref()
        .and_then(|template| template.execution_mode)
        .unwrap_or_else(ApprovalExecutionMode::from_env_default);
    if execution_mode.requires_saved_credential() && !config.save_password {
        return Err(AppError::bad_request(
            "APPROVAL_EXECUTION_MODE_REQUIRES_SAVED_CREDENTIAL: this mode runs without the requester's session, so the connection password must be saved server-side",
        ));
    }

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
        statements: statements.clone(),
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
        execution_mode,
        execution_error: None,
        executed_by: None,
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
    let mut view = ApprovalView::from_parts(request, steps);
    attach_approval_user_names(state, std::slice::from_mut(&mut view), &[]).await;
    Ok(view)
}

/// Agent-facing approval creation. It creates a pending request for the run's
/// bound target, or returns the existing open request for the same digest so a
/// retrying model cannot duplicate the queue.
pub(crate) async fn create_approval_for_agent(
    state: &Arc<WebState>,
    actor: &Actor,
    input: dbx_core::ai::agent_tools::GovernanceApprovalInput,
) -> Result<dbx_core::ai::agent_tools::GovernanceApprovalOutput, String> {
    require(actor, Permission::QueryWrite).map_err(|error| error.to_string())?;
    let sql = input.sql.trim().to_string();
    if sql.is_empty() {
        return Err("sql is required".to_string());
    }
    let db_type = state.app.configs.read().await.get(&input.connection_id).map(|config| config.db_type);
    let statements =
        db_type.map(|db_type| approval_statements(&sql, db_type, None)).unwrap_or_else(|| vec![sql.clone()]);
    let digest = dbx_core::governance::approval::statements_digest(&statements);
    if let Some(existing) = state
        .app
        .storage
        .find_open_approval_request(
            actor.id.clone(),
            input.connection_id.clone(),
            input.database.clone(),
            input.schema.clone(),
            digest,
        )
        .await
        .map_err(|error| error.to_string())?
    {
        return Ok(dbx_core::ai::agent_tools::GovernanceApprovalOutput {
            approval_id: existing.id,
            status: existing.status.as_str().to_string(),
            step_count: existing.step_count,
            execution_mode: existing.execution_mode.as_str().to_string(),
            deduplicated: true,
        });
    }
    let view = create_request_for_actor(
        state,
        actor,
        CreateApprovalRequest {
            connection_id: input.connection_id,
            database: input.database,
            schema_name: input.schema,
            sql,
            statements: None,
            justification: input.justification,
            template_id: None,
        },
    )
    .await
    .map_err(|error| error.to_string())?;
    Ok(dbx_core::ai::agent_tools::GovernanceApprovalOutput {
        approval_id: view.id,
        status: view.status,
        step_count: view.step_count,
        execution_mode: view.execution_mode,
        deduplicated: false,
    })
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
    /// Approval history view. Privileged audit roles see every request;
    /// everyone else sees their own.
    #[serde(default)]
    pub history: Option<bool>,
    /// Case-insensitive substring match over SQL, justification, request id,
    /// and requester id.
    #[serde(default)]
    pub q: Option<String>,
    #[serde(default)]
    pub from_ms: Option<i64>,
    #[serde(default)]
    pub to_ms: Option<i64>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub offset: Option<usize>,
}

pub async fn list_requests(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    AxumQuery(query): AxumQuery<ListApprovalsQuery>,
) -> Result<Json<Vec<ApprovalView>>, AppError> {
    build_approval_list(&state, &actor, query).await.map(Json)
}

/// Shared by the HTTP handler and the AI governance tools. Visibility is
/// enforced here, so both surfaces return exactly the same rows.
pub(crate) async fn build_approval_list(
    state: &WebState,
    actor: &Actor,
    query: ListApprovalsQuery,
) -> Result<Vec<ApprovalView>, AppError> {
    require(actor, Permission::ApprovalRead)?;
    let can_view_all = dbx_core::identity::can_view_all_audit(&actor.roles);
    let history = query.history.unwrap_or(false);
    let requester = query.mine.unwrap_or(false).then(|| actor.id.clone());
    let involved_actor_id = (history && !can_view_all).then(|| actor.id.clone());
    let status = query.status.filter(|value| ApprovalStatus::parse(value).is_some());
    let limit = query.limit.unwrap_or(if history { 50 } else { 200 }).clamp(1, 200);
    let offset = query.offset.unwrap_or(0);
    let mut requests = state
        .app
        .storage
        .list_approval_requests(dbx_core::storage::ApprovalRequestQuery {
            requester_id: requester,
            involved_actor_id,
            status,
            search: query.q,
            from_ms: query.from_ms,
            to_ms: query.to_ms,
            limit,
            offset,
        })
        .await
        .map_err(AppError::from)?;
    if !can_view_all && dbx_core::governance::assets::actor_is_managed(&actor) {
        let snapshot =
            dbx_core::governance::assets::load_asset_snapshot(&state.app, &actor.id).await.map_err(AppError::from)?;
        requests.retain(|request| {
            request.requester_id == actor.id || snapshot.can_navigate_connection(&request.connection_id)
        });
    }
    let ids: Vec<String> = requests.iter().map(|request| request.id.clone()).collect();
    let steps = state.app.storage.approval_steps_for_requests(ids.clone()).await.map_err(AppError::from)?;
    let decisions = state.app.storage.approval_step_decisions_for_requests(ids).await.map_err(AppError::from)?;
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
    attach_my_decisions(&mut views, &decisions, &actor.id);
    attach_approval_user_names(state, &mut views, &[]).await;
    Ok(views)
}

pub async fn get_request(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Path(request_id): Path<String>,
) -> Result<Json<ApprovalDetailView>, AppError> {
    build_approval_detail(&state, &actor, &request_id).await.map(Json)
}

/// Shared by the HTTP handler and the AI governance tools. Keeps the same
/// requester/approver/asset visibility rules.
pub(crate) async fn build_approval_detail(
    state: &WebState,
    actor: &Actor,
    request_id: &str,
) -> Result<ApprovalDetailView, AppError> {
    require(actor, Permission::ApprovalRead)?;
    let request = load_request(state, request_id).await?;
    let steps = state.app.storage.approval_steps_for_request(request.id.clone()).await.map_err(AppError::from)?;
    // The requester, an administrator, and anyone who may decide a step can
    // see the full timeline.
    let asset_visible = if dbx_core::governance::assets::actor_is_managed(&actor) {
        dbx_core::governance::assets::load_asset_snapshot(&state.app, &actor.id)
            .await
            .map(|snapshot| snapshot.can_navigate_connection(&request.connection_id))
            .unwrap_or(false)
    } else {
        true
    };
    let can_view = request.requester_id == actor.id
        || dbx_core::identity::can_view_all_audit(&actor.roles)
        || dbx_core::identity::has_permission(&actor.roles, Permission::AdminSettings)
        || asset_visible
        || steps.iter().any(|step| step.allows(&actor.id, &actor.roles));
    if !can_view {
        return Err(AppError::forbidden("APPROVAL_FORBIDDEN: this request is not assigned to you"));
    }
    let decisions =
        state.app.storage.approval_step_decisions_for_request(request.id.clone()).await.map_err(AppError::from)?;
    let decision_actor_ids: Vec<String> = decisions.iter().map(|decision| decision.actor_id.clone()).collect();
    let mut view = ApprovalView::from_parts(request, steps);
    attach_my_decisions(std::slice::from_mut(&mut view), &decisions, &actor.id);
    attach_approval_user_names(state, std::slice::from_mut(&mut view), &decision_actor_ids).await;
    Ok(ApprovalDetailView { request: view, decisions: decisions.iter().map(ApprovalDecisionView::from).collect() })
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

/// Who is pressing the execute button. The SQL always comes from the stored
/// request; the trigger only decides who is allowed to start it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExecutionTrigger {
    Submitter,
    LastApprover,
    Auto,
}

impl ExecutionTrigger {
    fn label(self) -> &'static str {
        match self {
            Self::Submitter => "submitter",
            Self::LastApprover => "last_approver",
            Self::Auto => "auto",
        }
    }
}

/// Load the connection on demand: a background execution may run before any
/// UI request populated `AppState::configs`.
async fn connection_config_for_execution(
    state: &WebState,
    connection_id: &str,
) -> Result<dbx_core::models::connection::ConnectionConfig, AppError> {
    if let Some(config) = state.app.configs.read().await.get(connection_id).cloned() {
        return Ok(config);
    }
    let configs = state.app.storage.load_connections().await.map_err(AppError::from)?;
    let mut current = state.app.configs.write().await;
    for config in configs {
        current.entry(config.id.clone()).or_insert(config);
    }
    current.get(connection_id).cloned().ok_or_else(|| AppError::not_found("connection not found"))
}

async fn fail_approval_request(state: &WebState, request: &ApprovalRequest, executed_by: &str, error: String) {
    let now = chrono::Utc::now().timestamp_millis();
    if let Err(failure) =
        state.app.storage.fail_approval_execution(request.id.clone(), executed_by.to_string(), error, now).await
    {
        log::warn!("approval execution state was not stored: {failure}");
    }
}

/// Executes the stored statements of an approved request exactly once.
///
/// The caller has already checked that the trigger matches the request's
/// execution mode. Everything the execution depends on is re-bound here:
/// statement digest, connection configuration, database, policy bundle, and
/// the rules that required approval. A mismatch fails the request instead of
/// running SQL that differs from what approvers saw.
async fn run_approved_request(
    state: &Arc<WebState>,
    request: ApprovalRequest,
    executor: &Actor,
    trigger: ExecutionTrigger,
) -> Result<ApprovalRequest, AppError> {
    if request.status != ApprovalStatus::Approved {
        return Err(AppError::conflict("APPROVAL_NOT_EXECUTABLE: the request is not approved or was already executed"));
    }
    let mode_matches = matches!(
        (trigger, request.execution_mode),
        (ExecutionTrigger::Submitter, ApprovalExecutionMode::Submitter)
            | (ExecutionTrigger::LastApprover, ApprovalExecutionMode::LastApprover)
            | (ExecutionTrigger::Auto, ApprovalExecutionMode::Auto)
    );
    if !mode_matches {
        return Err(AppError::conflict("APPROVAL_EXECUTION_MODE: this request uses a different execution mode"));
    }
    if trigger == ExecutionTrigger::Submitter && executor.id != request.requester_id {
        return Err(AppError::forbidden("APPROVAL_EXECUTION_FORBIDDEN: only the requester may execute this request"));
    }
    if request.statements.is_empty() {
        return Err(AppError::conflict("APPROVAL_STATEMENTS_MISSING: the request has no stored statements"));
    }
    if statements_digest(&request.statements) != request.sql_digest {
        let error = "APPROVAL_STATEMENTS_CHANGED: the stored statements no longer match the approved digest";
        fail_approval_request(state, &request, &executor.id, error.to_string()).await;
        return Err(AppError::conflict(error));
    }
    let config = connection_config_for_execution(state, &request.connection_id).await?;

    let mut rule_ids: Vec<String> = Vec::new();
    let mut policy_bundle_hash: Option<String> = None;
    for sql in &request.statements {
        let decision =
            dbx_core::governance::decide(&request.connection_id, &config, &request.database, config.db_type, sql);
        if decision.effect == dbx_core::governance::PolicyEffect::Block {
            let error = format!(
                "POLICY_DENIED: {} (rule {})",
                decision.reason,
                decision.rule_id.as_deref().unwrap_or("unknown")
            );
            fail_approval_request(state, &request, &executor.id, error.clone()).await;
            return Err(AppError::forbidden(format!("APPROVAL_EXECUTION_FAILED: {error}")));
        }
        rule_ids.extend(
            decision
                .matched
                .iter()
                .filter(|hit| hit.effect == dbx_core::governance::PolicyEffect::RequireApproval)
                .map(|hit| hit.rule_id.clone()),
        );
        policy_bundle_hash = Some(decision.policy_bundle_hash);
    }
    rule_ids.sort();
    rule_ids.dedup();
    let config_hash = dbx_core::governance::approval::connection_config_hash(&config);
    let current_hash = request_hash(&ApprovalBinding {
        connection_id: &request.connection_id,
        connection_config_hash: &config_hash,
        database: &request.database,
        schema: request.schema_name.as_deref(),
        statements_digest: &request.sql_digest,
        policy_bundle_hash: policy_bundle_hash.as_deref(),
        rule_ids: &rule_ids,
    });
    // Tickets created before the minimal-identity hash use either the previous
    // sanitized-config hash or the original legacy hash; accept all so
    // in-flight approvals survive an upgrade.
    let stable_hash = request_hash(&ApprovalBinding {
        connection_id: &request.connection_id,
        connection_config_hash: &dbx_core::governance::approval::stable_connection_config_hash(&config),
        database: &request.database,
        schema: request.schema_name.as_deref(),
        statements_digest: &request.sql_digest,
        policy_bundle_hash: policy_bundle_hash.as_deref(),
        rule_ids: &rule_ids,
    });
    let legacy_hash = request_hash(&ApprovalBinding {
        connection_id: &request.connection_id,
        connection_config_hash: &dbx_core::governance::approval::legacy_connection_config_hash(&config),
        database: &request.database,
        schema: request.schema_name.as_deref(),
        statements_digest: &request.sql_digest,
        policy_bundle_hash: policy_bundle_hash.as_deref(),
        rule_ids: &rule_ids,
    });
    if current_hash != request.request_hash
        && stable_hash != request.request_hash
        && legacy_hash != request.request_hash
    {
        log::warn!(
            "[approval] binding mismatch id={} stored={} current={} stable={} legacy={} connection={} database={} schema={:?}",
            request.id,
            request.request_hash,
            current_hash,
            stable_hash,
            legacy_hash,
            request.connection_id,
            request.database,
            request.schema_name
        );
        let error = "APPROVAL_BINDING_MISMATCH: the connection, database, policy, or rules changed since approval";
        fail_approval_request(state, &request, &executor.id, error.to_string()).await;
        return Err(AppError::conflict(error));
    }

    // The approval covers DDL even when the requester only has query:write.
    if let Err(error) = dbx_core::governance::authorize_connection_scope(
        &state.app,
        Some(&request.requester_id),
        &request.connection_id,
        Some(&request.database),
        request.schema_name.as_deref(),
        &request.statements,
        Some(config.db_type),
        true,
    )
    .await
    {
        return Err(AppError::forbidden(format!("APPROVAL_EXECUTION_DENIED: {error}")));
    }

    let now = chrono::Utc::now().timestamp_millis();
    if !state.app.storage.claim_approval_execution(request.id.clone(), now).await.map_err(AppError::from)? {
        return Err(AppError::conflict("APPROVAL_ALREADY_EXECUTED: this request was already executed or is executing"));
    }

    let requester = state.app.storage.user_by_id(request.requester_id.clone()).await.ok().flatten();
    let roles = state.app.storage.role_codes_for_user(request.requester_id.clone()).await.unwrap_or_default();
    let asset_roles =
        state.app.storage.asset_role_codes_for_user(request.requester_id.clone()).await.unwrap_or_default();
    let requester_actor = Actor {
        id: request.requester_id.clone(),
        display_name: requester.map(|user| user.display_name).unwrap_or_else(|| request.requester_id.clone()),
        kind: ActorKind::Human,
        roles,
        asset_roles,
        tenant_id: None,
        session_id: None,
        auth_method: "approval".to_string(),
    };
    let execution_id = uuid::Uuid::new_v4().to_string();
    let mut context = dbx_core::audit::current_audit_context().unwrap_or_else(|| AuditContext {
        actor: requester_actor.clone(),
        source: AuditSource::Approval,
        client_ip: None,
        user_agent: None,
        request_id: None,
        execution_id: None,
    });
    context.actor = requester_actor;
    context.source = AuditSource::Approval;
    context.execution_id = Some(execution_id);
    let executed_by = if trigger == ExecutionTrigger::Auto { "system:auto".to_string() } else { executor.id.clone() };

    let result = dbx_core::audit::with_audit_context(
        context.clone(),
        dbx_core::query::execute_approved_statements(
            &state.app,
            &request.connection_id,
            &request.database,
            &request.statements,
            request.schema_name.as_deref(),
            None,
        ),
    )
    .await;
    let (status, outcome, decision, error) = match &result {
        Ok(_) => (ApprovalStatus::Executed, AuditOutcome::Success, AuditDecision::Allowed, None),
        Err(error) => (ApprovalStatus::ExecutionFailed, AuditOutcome::Error, AuditDecision::Error, Some(error.clone())),
    };
    if let Err(failure) = state
        .app
        .storage
        .finish_approval_execution(
            request.id.clone(),
            status,
            executed_by.clone(),
            error.clone(),
            chrono::Utc::now().timestamp_millis(),
        )
        .await
    {
        log::warn!("approval execution state was not stored: {failure}");
    }

    let mut event = AuditEventInsert::new(&context, AuditOperation::Approval, decision, outcome);
    event.resource_type = Some("approval".to_string());
    event.resource_id = Some(request.id.clone());
    event.approval_id = Some(request.id.clone());
    event.details_json = Some(
        serde_json::json!({
            "approval_id": request.id,
            "trigger": trigger.label(),
            "execution_mode": request.execution_mode.as_str(),
            "executed_by": executed_by,
            "statement_count": request.statement_count,
            "error": error,
        })
        .to_string(),
    );
    state.app.record_audit(event);

    let refreshed = state
        .app
        .storage
        .approval_request_by_id(request.id.clone())
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("approval request not found"))?;
    notify_approval(if result.is_ok() { "approval.executed" } else { "approval.execution_failed" }, &refreshed);
    match result {
        Ok(_) => Ok(refreshed),
        Err(error) => Err(AppError::conflict(format!("APPROVAL_EXECUTION_FAILED: {error}"))),
    }
}

fn spawn_approval_execution(
    state: Arc<WebState>,
    request: ApprovalRequest,
    executor: Actor,
    trigger: ExecutionTrigger,
) {
    tokio::spawn(async move {
        if let Err(error) = run_approved_request(&state, request, &executor, trigger).await {
            log::warn!("approval execution did not complete: {error}");
        }
    });
}

pub async fn execute_request(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Path(request_id): Path<String>,
) -> Result<Json<ApprovalView>, AppError> {
    require(&actor, Permission::QueryWrite)?;
    let request = load_request(&state, &request_id).await?;
    if request.requester_id != actor.id {
        return Err(AppError::forbidden("APPROVAL_EXECUTION_FORBIDDEN: only the requester may execute this request"));
    }
    if request.execution_mode != ApprovalExecutionMode::Submitter {
        return Err(AppError::conflict(
            "APPROVAL_EXECUTION_MODE: this request is executed by its execution mode, not by the requester",
        ));
    }
    let refreshed = run_approved_request(&state, request, &actor, ExecutionTrigger::Submitter).await?;
    let steps = state.app.storage.approval_steps_for_request(refreshed.id.clone()).await.map_err(AppError::from)?;
    let mut view = ApprovalView::from_parts(refreshed, steps);
    attach_approval_user_names(state.as_ref(), std::slice::from_mut(&mut view), &[]).await;
    Ok(Json(view))
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
    state: &Arc<WebState>,
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
    // DMS-style execution modes: the last approver can trigger execution in
    // the same click, or the server can run it immediately. Both need a
    // server-held credential, checked when the request was created.
    if outcome.request_status == ApprovalStatus::Approved {
        let trigger = match refreshed.execution_mode {
            ApprovalExecutionMode::Auto => Some(ExecutionTrigger::Auto),
            ApprovalExecutionMode::LastApprover => Some(ExecutionTrigger::LastApprover),
            ApprovalExecutionMode::Submitter => None,
        };
        if let Some(trigger) = trigger {
            spawn_approval_execution(state.clone(), refreshed.clone(), actor.clone(), trigger);
        }
    }
    let decisions =
        state.app.storage.approval_step_decisions_for_request(refreshed.id.clone()).await.unwrap_or_default();
    let mut view = ApprovalView::from_parts(refreshed, steps);
    attach_my_decisions(std::slice::from_mut(&mut view), &decisions, &actor.id);
    attach_approval_user_names(state, std::slice::from_mut(&mut view), &[]).await;
    Ok(view)
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
        return Err(AppError::conflict("APPROVAL_NOT_APPROVED: the request is not approved or was already executed"));
    }
    if request.execution_mode != ApprovalExecutionMode::Submitter {
        return Err(AppError::conflict(
            "APPROVAL_EXECUTION_MODE: this request is executed by the server or the last approver; no client token is issued",
        ));
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
    pub execution_mode: Option<String>,
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
            execution_mode: template.execution_mode.map(|mode| mode.as_str().to_string()),
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
    /// `submitter`, `last_approver`, `auto`, or absent to use the server default.
    #[serde(default)]
    pub execution_mode: Option<String>,
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

fn template_execution_mode(value: Option<&str>) -> Result<Option<ApprovalExecutionMode>, AppError> {
    match value.map(str::trim).filter(|value| !value.is_empty()) {
        None => Ok(None),
        Some(value) => ApprovalExecutionMode::parse(value).map(Some).ok_or_else(|| {
            AppError::bad_request(
                "APPROVAL_TEMPLATE_INVALID: execution_mode must be `submitter`, `last_approver`, or `auto`",
            )
        }),
    }
}

pub async fn list_templates(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
) -> Result<Json<Vec<TemplateView>>, AppError> {
    build_template_views(&state, &actor).await.map(Json)
}

/// Shared by the HTTP handler and the AI governance tools.
pub(crate) async fn build_template_views(state: &WebState, actor: &Actor) -> Result<Vec<TemplateView>, AppError> {
    require(actor, Permission::ApprovalRead)?;
    let templates = state.app.storage.list_approval_templates().await.map_err(AppError::from)?;
    Ok(templates.into_iter().map(TemplateView::from).collect())
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
    let execution_mode = template_execution_mode(body.execution_mode.as_deref())?;
    let now = chrono::Utc::now().timestamp_millis();
    let template = ApprovalTemplate {
        id: uuid::Uuid::new_v4().to_string(),
        name: body.name.trim().to_string(),
        scope_type,
        scope_id,
        steps,
        sla_secs: body.sla_secs,
        execution_mode,
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
    let execution_mode = template_execution_mode(body.execution_mode.as_deref())?;
    let template = ApprovalTemplate {
        id: existing.id,
        name: body.name.trim().to_string(),
        scope_type,
        scope_id,
        steps,
        sla_secs: body.sla_secs,
        execution_mode,
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
    let in_use = dbx_core::governance::policy::current_policy()
        .rules()
        .iter()
        .any(|rule| rule.approval_template_id.as_deref() == Some(template_id.as_str()));
    if in_use {
        return Err(AppError::conflict(
            "APPROVAL_TEMPLATE_IN_USE: remove the policy rule binding before deleting this template",
        ));
    }
    if !state.app.storage.delete_approval_template(template_id).await.map_err(AppError::from)? {
        return Err(AppError::not_found("approval template not found"));
    }
    Ok(Json(serde_json::json!({ "ok": true })))
}

#[cfg(test)]
mod tests {
    use super::approval_statements;
    use dbx_core::models::connection::DatabaseType;

    #[test]
    fn approval_statements_splits_a_batch_with_the_executor_rules() {
        let statements = approval_statements(
            "CREATE TABLE product_test(id int); INSERT INTO product_test VALUES (1);",
            DatabaseType::Postgres,
            None,
        );
        assert_eq!(statements.len(), 2, "{statements:?}");
        assert!(statements[0].starts_with("CREATE TABLE"));
        assert!(statements[1].starts_with("INSERT INTO"));
    }

    #[test]
    fn approval_statements_keeps_a_routine_body_intact() {
        let sql = "CREATE FUNCTION f() RETURNS int LANGUAGE sql AS $$ SELECT 1; $$";
        assert_eq!(approval_statements(sql, DatabaseType::Postgres, None), vec![sql.to_string()]);
    }

    #[test]
    fn approval_statements_prefers_an_explicit_batch_and_falls_back_for_empty_sql() {
        let provided = vec!["SELECT 1".to_string(), "SELECT 2".to_string()];
        assert_eq!(approval_statements("ignored", DatabaseType::Postgres, Some(provided.clone())), provided);
        assert_eq!(approval_statements("", DatabaseType::Postgres, None), vec![String::new()]);
    }
}
