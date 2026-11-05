//! Column-mask and read-row-filter policy administration.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::Extension;
use axum::Json;
use dbx_core::audit::{
    Actor, AuditContext, AuditDecision, AuditEventInsert, AuditOperation, AuditOutcome, AuditSource,
};
use dbx_core::governance::data_policies::{DataPolicy, DataPolicyKind};
use dbx_core::identity::Permission;
use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::state::WebState;

fn require_admin(actor: &Actor) -> Result<(), AppError> {
    if dbx_core::identity::has_permission(&actor.roles, Permission::AdminUsers) {
        Ok(())
    } else {
        Err(AppError::forbidden("PERMISSION_DENIED: admin:users is required"))
    }
}

#[derive(Debug, Default, Deserialize)]
pub struct DataPolicyListQuery {
    #[serde(default)]
    pub connection_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DataPolicyInput {
    pub name: String,
    pub kind: String,
    pub connection_id: String,
    #[serde(default)]
    pub database_name: Option<String>,
    #[serde(default)]
    pub schema_name: Option<String>,
    pub table_name: String,
    #[serde(default)]
    pub name_pattern: bool,
    pub column_name: String,
    #[serde(default)]
    pub mask_type: Option<String>,
    #[serde(default)]
    pub replacement: Option<String>,
    #[serde(default)]
    pub allowed_values: Vec<String>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool {
    true
}

#[derive(Debug, Serialize)]
pub struct DataPolicyView {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub connection_id: String,
    pub database_name: Option<String>,
    pub schema_name: Option<String>,
    pub table_name: String,
    pub name_pattern: bool,
    pub column_name: String,
    pub mask_type: String,
    pub replacement: String,
    pub allowed_values: Vec<String>,
    pub enabled: bool,
    pub created_by: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl From<DataPolicy> for DataPolicyView {
    fn from(policy: DataPolicy) -> Self {
        Self {
            id: policy.id,
            name: policy.name,
            kind: policy.kind.as_str().to_string(),
            connection_id: policy.connection_id,
            database_name: policy.database_name,
            schema_name: policy.schema_name,
            table_name: policy.table_name,
            name_pattern: policy.name_pattern,
            column_name: policy.column_name,
            mask_type: policy.mask_type,
            replacement: policy.replacement,
            allowed_values: policy.allowed_values,
            enabled: policy.enabled,
            created_by: policy.created_by,
            created_at: policy.created_at,
            updated_at: policy.updated_at,
        }
    }
}

async fn connection_exists(state: &WebState, connection_id: &str) -> Result<bool, AppError> {
    if state.app.configs.read().await.contains_key(connection_id) {
        return Ok(true);
    }
    Ok(state
        .app
        .storage
        .load_connections()
        .await
        .map_err(AppError::from)?
        .iter()
        .any(|connection| connection.id == connection_id))
}

fn clean(value: Option<String>) -> Option<String> {
    value.map(|value| value.trim().to_string()).filter(|value| !value.is_empty())
}

async fn validate_policy(
    state: &WebState,
    actor: &Actor,
    body: DataPolicyInput,
    existing: Option<&DataPolicy>,
) -> Result<DataPolicy, AppError> {
    let kind = DataPolicyKind::parse(body.kind.trim())
        .ok_or_else(|| AppError::bad_request("kind must be mask or row_filter"))?;
    let name = body.name.trim();
    if name.is_empty() {
        return Err(AppError::bad_request("name is required"));
    }
    if name.chars().count() > 120 {
        return Err(AppError::bad_request("name must be at most 120 characters"));
    }
    let connection_id = body.connection_id.trim();
    if connection_id.is_empty() || !connection_exists(state, connection_id).await? {
        return Err(AppError::bad_request("unknown connection"));
    }
    let table_name = body.table_name.trim();
    if table_name.is_empty() {
        return Err(AppError::bad_request("table_name is required"));
    }
    let column_name = body.column_name.trim();
    if column_name.is_empty() {
        return Err(AppError::bad_request("column_name is required"));
    }
    let (mask_type, replacement, allowed_values) = match kind {
        DataPolicyKind::Mask => {
            let mask_type = body.mask_type.as_deref().unwrap_or("full").trim().to_string();
            if !matches!(mask_type.as_str(), "full" | "partial" | "email") {
                return Err(AppError::bad_request("mask_type must be full, partial, or email"));
            }
            let replacement = body.replacement.as_deref().unwrap_or("***").trim().to_string();
            let replacement = if replacement.is_empty() { "***".to_string() } else { replacement };
            (mask_type, replacement, Vec::new())
        }
        DataPolicyKind::RowFilter => {
            let mut allowed: Vec<String> = body
                .allowed_values
                .iter()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .collect();
            allowed.sort();
            allowed.dedup();
            if allowed.is_empty() {
                return Err(AppError::bad_request("allowed_values is required for a row filter"));
            }
            ("full".to_string(), "***".to_string(), allowed)
        }
    };
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let created_at = existing.map(|policy| policy.created_at.clone()).unwrap_or_else(|| now.clone());
    let created_by = existing.and_then(|policy| policy.created_by.clone()).or_else(|| Some(actor.id.clone()));
    Ok(DataPolicy {
        id: existing.map(|policy| policy.id.clone()).unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
        name: name.to_string(),
        kind,
        connection_id: connection_id.to_string(),
        database_name: clean(body.database_name),
        schema_name: clean(body.schema_name),
        table_name: table_name.to_string(),
        name_pattern: body.name_pattern,
        column_name: column_name.to_string(),
        mask_type,
        replacement,
        allowed_values,
        enabled: body.enabled,
        created_by,
        created_at,
        updated_at: now,
    })
}

fn record_audit(state: &WebState, actor: &Actor, action: &str, policy: &DataPolicy) {
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
    event.resource_type = Some("data_policy".to_string());
    event.resource_id = Some(policy.id.clone());
    event.details_json = Some(
        serde_json::json!({
            "action": action,
            "name": policy.name,
            "kind": policy.kind.as_str(),
            "connection_id": policy.connection_id,
            "database_name": policy.database_name,
            "schema_name": policy.schema_name,
            "table_name": policy.table_name,
            "column_name": policy.column_name,
        })
        .to_string(),
    );
    state.app.record_audit(event);
}

pub async fn list_data_policies(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Query(query): Query<DataPolicyListQuery>,
) -> Result<Json<Vec<DataPolicyView>>, AppError> {
    require_admin(&actor)?;
    let policies = state.app.storage.list_data_policies(clean(query.connection_id)).await.map_err(AppError::from)?;
    Ok(Json(policies.into_iter().map(DataPolicyView::from).collect()))
}

pub async fn create_data_policy(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Json(body): Json<DataPolicyInput>,
) -> Result<Json<DataPolicyView>, AppError> {
    require_admin(&actor)?;
    let policy = validate_policy(&state, &actor, body, None).await?;
    state.app.storage.create_data_policy(policy.clone()).await.map_err(AppError::from)?;
    record_audit(&state, &actor, "created", &policy);
    Ok(Json(DataPolicyView::from(policy)))
}

pub async fn update_data_policy(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Path(policy_id): Path<String>,
    Json(body): Json<DataPolicyInput>,
) -> Result<Json<DataPolicyView>, AppError> {
    require_admin(&actor)?;
    let existing = state
        .app
        .storage
        .data_policy_by_id(policy_id)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("data policy not found"))?;
    let policy = validate_policy(&state, &actor, body, Some(&existing)).await?;
    if !state.app.storage.update_data_policy(policy.clone()).await.map_err(AppError::from)? {
        return Err(AppError::not_found("data policy not found"));
    }
    record_audit(&state, &actor, "updated", &policy);
    Ok(Json(DataPolicyView::from(policy)))
}

pub async fn delete_data_policy(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Path(policy_id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    require_admin(&actor)?;
    let policy = state
        .app
        .storage
        .data_policy_by_id(policy_id.clone())
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("data policy not found"))?;
    if !state.app.storage.delete_data_policy(policy_id).await.map_err(AppError::from)? {
        return Err(AppError::not_found("data policy not found"));
    }
    record_audit(&state, &actor, "deleted", &policy);
    Ok(Json(serde_json::json!({ "ok": true })))
}
