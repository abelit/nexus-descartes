//! Policy documents: versioned publication, rollback, and the effective view.

use std::sync::Arc;

use axum::extract::{Query as AxumQuery, State};
use axum::Extension;
use axum::Json;
use dbx_core::audit::Actor;
use dbx_core::governance::{CompiledPolicy, PolicyDocument, PolicyEffect};
use dbx_core::identity::Permission;
use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::state::WebState;

fn require(actor: &Actor, permission: Permission) -> Result<(), AppError> {
    if dbx_core::identity::has_permission(&actor.roles, permission) {
        Ok(())
    } else {
        Err(AppError::forbidden(format!("PERMISSION_DENIED: {}", permission.as_str())))
    }
}

#[derive(Debug, Serialize)]
pub struct PolicyVersionView {
    pub id: String,
    pub scope_type: String,
    pub scope_id: String,
    pub version: i64,
    pub created_by: Option<String>,
    pub created_at_ms: i64,
    pub note: String,
    pub document: serde_json::Value,
}

#[derive(Debug, Default, Deserialize)]
pub struct ListPoliciesQuery {
    #[serde(default = "global_scope")]
    pub scope_type: String,
    #[serde(default)]
    pub scope_id: String,
    #[serde(default)]
    pub limit: Option<usize>,
}

fn global_scope() -> String {
    "global".to_string()
}

pub async fn list_policies(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    AxumQuery(query): AxumQuery<ListPoliciesQuery>,
) -> Result<Json<Vec<PolicyVersionView>>, AppError> {
    require(&actor, Permission::PolicyRead)?;
    let rows = state
        .app
        .storage
        .list_policy_documents(query.scope_type, query.scope_id, query.limit.unwrap_or(50))
        .await
        .map_err(AppError::from)?;
    Ok(Json(
        rows.into_iter()
            .map(|row| PolicyVersionView {
                id: row.id,
                scope_type: row.scope_type,
                scope_id: row.scope_id,
                version: row.version,
                created_by: row.created_by,
                created_at_ms: row.created_at_ms,
                note: row.note,
                document: serde_json::from_str(&row.document_json).unwrap_or(serde_json::Value::Null),
            })
            .collect(),
    ))
}

#[derive(Debug, Deserialize)]
pub struct PublishPolicyRequest {
    #[serde(default = "global_scope")]
    pub scope_type: String,
    #[serde(default)]
    pub scope_id: String,
    pub document: serde_json::Value,
    #[serde(default)]
    pub note: String,
}

pub async fn publish_policy(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Json(body): Json<PublishPolicyRequest>,
) -> Result<Json<PolicyVersionView>, AppError> {
    require(&actor, Permission::PolicyPublish)?;
    validate_scope(&body.scope_type, &body.scope_id)?;
    let document: PolicyDocument = serde_json::from_value(body.document.clone())
        .map_err(|error| AppError::bad_request(format!("POLICY_DOCUMENT_INVALID: {error}")))?;
    validate_rule_templates(&state, &body.scope_type, &body.scope_id, &document).await?;
    let document_json = serde_json::to_string(&document).map_err(|error| AppError::internal(error.to_string()))?;

    // Compile the document together with every other scope before publishing:
    // an invalid policy must never become the effective one.
    let mut documents = latest_documents(&state).await?;
    let scope = scope_of(&body.scope_type, &body.scope_id);
    documents.retain(|(existing, _, _)| existing != &scope);
    documents.push((scope, i64::MAX, document_json.clone()));
    CompiledPolicy::compile(&documents).map_err(|error| AppError::bad_request(error))?;

    let version = state
        .app
        .storage
        .publish_policy(
            body.scope_type.clone(),
            body.scope_id.clone(),
            document_json,
            actor.id.clone(),
            body.note.clone(),
        )
        .await
        .map_err(AppError::from)?;
    reload_policy(&state).await?;
    Ok(Json(PolicyVersionView {
        id: String::new(),
        scope_type: body.scope_type,
        scope_id: body.scope_id,
        version,
        created_by: Some(actor.id),
        created_at_ms: chrono::Utc::now().timestamp_millis(),
        note: body.note,
        document: body.document,
    }))
}

#[derive(Debug, Deserialize)]
pub struct RollbackPolicyRequest {
    #[serde(default = "global_scope")]
    pub scope_type: String,
    #[serde(default)]
    pub scope_id: String,
    pub version: i64,
    #[serde(default)]
    pub note: String,
}

pub async fn rollback_policy(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Json(body): Json<RollbackPolicyRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    require(&actor, Permission::PolicyPublish)?;
    validate_scope(&body.scope_type, &body.scope_id)?;
    let source = state
        .app
        .storage
        .policy_document_at(body.scope_type.clone(), body.scope_id.clone(), body.version)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("POLICY_VERSION_NOT_FOUND"))?;
    let document: PolicyDocument = serde_json::from_str(&source.document_json)
        .map_err(|error| AppError::bad_request(format!("POLICY_DOCUMENT_INVALID: {error}")))?;
    validate_rule_templates(&state, &body.scope_type, &body.scope_id, &document).await?;
    let version = state
        .app
        .storage
        .rollback_policy(
            body.scope_type.clone(),
            body.scope_id.clone(),
            body.version,
            actor.id.clone(),
            if body.note.trim().is_empty() { format!("rollback to v{}", body.version) } else { body.note },
        )
        .await
        .map_err(AppError::from)?;
    reload_policy(&state).await?;
    Ok(Json(serde_json::json!({
        "scope_type": body.scope_type,
        "scope_id": body.scope_id,
        "version": version,
    })))
}

#[derive(Debug, Serialize)]
pub struct EffectiveRuleView {
    pub id: String,
    pub enabled: bool,
    pub priority: i32,
    pub effect: String,
    pub scope: dbx_core::governance::RuleScope,
    pub r#match: dbx_core::governance::RuleMatch,
    pub message: String,
    pub approval_template_id: Option<String>,
    pub builtin: bool,
}

#[derive(Debug, Serialize)]
pub struct EffectivePolicyView {
    pub policy_bundle_hash: String,
    pub rules: Vec<EffectiveRuleView>,
    pub documents: Vec<serde_json::Value>,
}

pub async fn effective_policy(Extension(actor): Extension<Actor>) -> Result<Json<EffectivePolicyView>, AppError> {
    require(&actor, Permission::PolicyRead)?;
    let policy = dbx_core::governance::policy::current_policy();
    Ok(Json(EffectivePolicyView {
        policy_bundle_hash: policy.bundle_hash().to_string(),
        rules: policy
            .rules()
            .iter()
            .map(|rule| EffectiveRuleView {
                id: rule.id.clone(),
                enabled: rule.enabled,
                priority: rule.priority,
                effect: rule.effect.as_str().to_string(),
                scope: rule.scope.clone(),
                r#match: rule.rule_match.clone(),
                message: rule.message.clone(),
                approval_template_id: rule.approval_template_id.clone(),
                builtin: rule.builtin,
            })
            .collect(),
        documents: policy
            .documents()
            .iter()
            .map(|scoped| {
                serde_json::json!({
                    "scope": scoped.scope,
                    "version": scoped.version,
                    "rules": scoped.document.rules.len(),
                })
            })
            .collect(),
    }))
}

fn validate_scope(scope_type: &str, scope_id: &str) -> Result<(), AppError> {
    match scope_type {
        "global" if scope_id.trim().is_empty() => Ok(()),
        "global" => Err(AppError::bad_request("global policies must not specify scope_id")),
        "connection" | "database" if !scope_id.trim().is_empty() => Ok(()),
        "connection" | "database" => Err(AppError::bad_request("scope_id is required for this scope type")),
        other => Err(AppError::bad_request(format!("Unknown scope type '{other}'"))),
    }
}

fn scope_of(scope_type: &str, scope_id: &str) -> dbx_core::governance::RuleScope {
    match scope_type {
        "connection" => dbx_core::governance::RuleScope::Connection(scope_id.to_string()),
        "database" => dbx_core::governance::RuleScope::Database(scope_id.to_string()),
        _ => dbx_core::governance::RuleScope::Global,
    }
}

/// Validate `approval_template_id` bindings before a policy document becomes
/// effective. A bound template must exist, be enabled, and be usable from the
/// document's scope: global documents may only bind global templates, while
/// connection/database documents may also bind a template for their own
/// connection.
async fn validate_rule_templates(
    state: &WebState,
    scope_type: &str,
    scope_id: &str,
    document: &PolicyDocument,
) -> Result<(), AppError> {
    if !document.rules.iter().any(|rule| rule.approval_template_id.as_deref().is_some_and(|id| !id.trim().is_empty())) {
        return Ok(());
    }
    let templates = state.app.storage.list_approval_templates().await.map_err(AppError::from)?;
    let connection_id = match scope_type {
        "connection" => Some(scope_id),
        "database" => Some(scope_id.split("::").next().unwrap_or(scope_id)),
        _ => None,
    };
    for rule in &document.rules {
        let Some(template_id) = rule.approval_template_id.as_deref().map(str::trim).filter(|id| !id.is_empty()) else {
            continue;
        };
        if rule.action != PolicyEffect::RequireApproval {
            return Err(AppError::bad_request(format!(
                "POLICY_TEMPLATE_NOT_APPLICABLE: rule {} binds an approval template but its action is not require_approval",
                rule.id
            )));
        }
        let template = templates.iter().find(|template| template.id == template_id).ok_or_else(|| {
            AppError::bad_request(format!(
                "POLICY_TEMPLATE_MISSING: rule {} references unknown approval template {template_id}",
                rule.id
            ))
        })?;
        if !template.enabled {
            return Err(AppError::bad_request(format!(
                "POLICY_TEMPLATE_DISABLED: rule {} references disabled approval template {template_id}",
                rule.id
            )));
        }
        let scope_allows = template.scope_type == "global"
            || (template.scope_type == "connection" && connection_id == Some(template.scope_id.as_str()));
        if !scope_allows {
            return Err(AppError::bad_request(format!(
                "POLICY_TEMPLATE_SCOPE_MISMATCH: template {template_id} is scoped to another connection"
            )));
        }
    }
    Ok(())
}

/// Latest published document of every scope, as compilation input.
pub(crate) async fn latest_documents(
    state: &WebState,
) -> Result<Vec<(dbx_core::governance::RuleScope, i64, String)>, AppError> {
    let rows = state.app.storage.latest_policy_documents().await.map_err(AppError::from)?;
    Ok(rows.into_iter().map(|row| (scope_of(&row.scope_type, &row.scope_id), row.version, row.document_json)).collect())
}

pub(crate) async fn reload_policy(state: &WebState) -> Result<(), AppError> {
    let compiled =
        dbx_core::governance::policy::load_compiled_policy(&state.app.storage).await.map_err(AppError::from)?;
    dbx_core::governance::policy::install_policy(compiled);
    Ok(())
}
