//! Policy simulation: answer "what would the rules decide?" without executing.
//!
//! The UI uses this to show the matched rules before a statement is run. It
//! never touches a database.

use std::sync::Arc;

use axum::extract::State;
use axum::Extension;
use axum::Json;
use dbx_core::audit::Actor;
use dbx_core::identity::Permission;
use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::state::WebState;

#[derive(Debug, Deserialize)]
pub struct SimulateRequest {
    pub connection_id: String,
    #[serde(default)]
    pub database: String,
    pub sql: String,
}

#[derive(Debug, Serialize)]
pub struct RuleHitView {
    pub rule_id: String,
    pub effect: String,
    pub reason: String,
}

#[derive(Debug, Serialize)]
pub struct DecisionView {
    pub effect: String,
    pub rule_id: Option<String>,
    pub reason: String,
    pub matched: Vec<RuleHitView>,
    pub production: bool,
    pub enforcement: bool,
}

pub async fn simulate(
    State(state): State<Arc<WebState>>,
    Extension(actor): Extension<Actor>,
    Json(request): Json<SimulateRequest>,
) -> Result<Json<DecisionView>, AppError> {
    if !dbx_core::identity::has_permission(&actor.roles, Permission::QueryRead) {
        return Err(AppError::forbidden("PERMISSION_DENIED: query:read"));
    }
    let config = {
        let configs = state.app.configs.read().await;
        configs.get(&request.connection_id).cloned()
    }
    .ok_or_else(|| AppError::not_found("connection not found"))?;

    let production = dbx_core::production_safety::is_production_database(&config, &request.database);
    let decision =
        dbx_core::governance::decide(&request.connection_id, &config, &request.database, config.db_type, &request.sql);
    Ok(Json(DecisionView {
        effect: decision.effect.as_str().to_string(),
        rule_id: decision.rule_id,
        reason: decision.reason,
        matched: decision
            .matched
            .into_iter()
            .map(|hit| RuleHitView {
                rule_id: hit.rule_id,
                effect: hit.effect.as_str().to_string(),
                reason: hit.reason,
            })
            .collect(),
        production,
        enforcement: dbx_core::governance::enforcement_enabled(),
    }))
}
