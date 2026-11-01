//! Published policy documents and the compiled rule set.
//!
//! A document is an immutable version bound to one scope (global, connection,
//! or database). Publishing writes a new version; rollback publishes a copy of
//! an old version. Compilation merges the built-in floor with the latest
//! published document of every scope and produces a `policy_bundle_hash` that
//! audit events and approvals bind to.

use std::sync::{Arc, LazyLock, RwLock};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::rules::{builtin_rules, evaluate, PolicyDecision, PolicyEffect, Rule, RuleMatch, RuleScope};
use crate::models::connection::DatabaseType;

const ENGINE_VERSION: &str = "rules-v2";

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDocument {
    #[serde(default)]
    pub rules: Vec<StoredRule>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredRule {
    pub id: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub priority: i32,
    #[serde(default)]
    pub r#match: RuleMatch,
    pub action: PolicyEffect,
    pub message: String,
}

fn default_enabled() -> bool {
    true
}

impl StoredRule {
    fn into_rule(self, scope: RuleScope) -> Rule {
        Rule {
            id: self.id,
            enabled: self.enabled,
            priority: self.priority,
            effect: self.action,
            rule_match: self.r#match,
            message: self.message,
            scope,
            builtin: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopedPolicy {
    pub scope: RuleScope,
    pub version: i64,
    pub document: PolicyDocument,
}

#[derive(Clone, Debug)]
pub struct CompiledPolicy {
    rules: Vec<Rule>,
    bundle_hash: String,
    documents: Vec<ScopedPolicy>,
}

impl CompiledPolicy {
    pub fn builtin_only() -> Self {
        Self::compile(&[]).unwrap_or_else(|_| Self {
            rules: builtin_rules(),
            bundle_hash: sha256_hex(format!("{ENGINE_VERSION}:builtin").as_bytes()),
            documents: Vec::new(),
        })
    }

    /// `documents` are the latest published version of each scope.
    pub fn compile(documents: &[(RuleScope, i64, String)]) -> Result<Self, String> {
        let mut parsed = Vec::with_capacity(documents.len());
        for (scope, version, json) in documents {
            let document: PolicyDocument =
                serde_json::from_str(json).map_err(|error| format!("POLICY_DOCUMENT_INVALID: {error}"))?;
            validate(&document)?;
            parsed.push(ScopedPolicy { scope: scope.clone(), version: *version, document });
        }
        // Deterministic order: scope rank then version.
        parsed.sort_by(|left, right| {
            scope_rank(&left.scope).cmp(&scope_rank(&right.scope)).then_with(|| left.version.cmp(&right.version))
        });

        let mut rules = builtin_rules();
        // A stored rule replaces the built-in with the same id (disabling a
        // built-in is done by reusing its id with `enabled: false`).
        for scoped in &parsed {
            for stored in &scoped.document.rules {
                if let Some(existing) = rules.iter_mut().find(|rule| rule.id == stored.id) {
                    *existing = stored.clone().into_rule(scoped.scope.clone());
                } else {
                    rules.push(stored.clone().into_rule(scoped.scope.clone()));
                }
            }
        }

        let bundle_hash = bundle_hash(&parsed);
        Ok(Self { rules, bundle_hash, documents: parsed })
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    pub fn documents(&self) -> &[ScopedPolicy] {
        &self.documents
    }

    pub fn bundle_hash(&self) -> &str {
        &self.bundle_hash
    }

    pub fn decide(
        &self,
        connection_id: &str,
        database: &str,
        db_type: DatabaseType,
        sql: &str,
        is_production: bool,
    ) -> PolicyDecision {
        let context = super::rules::RuleContext { connection_id, database, db_type, sql, is_production };
        evaluate(&self.rules, &context, &self.bundle_hash)
    }
}

/// The process-wide compiled policy.
///
/// A single Web process owns one policy set; publishing replaces the arc
/// atomically, so in-flight decisions keep the bundle they started with. A
/// multi-instance deployment would move this behind its shared control plane.
static CURRENT: LazyLock<RwLock<Arc<CompiledPolicy>>> =
    LazyLock::new(|| RwLock::new(Arc::new(CompiledPolicy::builtin_only())));

pub fn current_policy() -> Arc<CompiledPolicy> {
    CURRENT.read().unwrap_or_else(|poisoned| poisoned.into_inner()).clone()
}

pub fn install_policy(policy: CompiledPolicy) {
    *CURRENT.write().unwrap_or_else(|poisoned| poisoned.into_inner()) = Arc::new(policy);
}

/// Loads every scope's latest published document and compiles the rule set.
pub async fn load_compiled_policy(storage: &crate::persistence::storage::Storage) -> Result<CompiledPolicy, String> {
    let rows = storage.latest_policy_documents().await?;
    let mut documents = Vec::with_capacity(rows.len());
    for row in rows {
        let scope = match row.scope_type.as_str() {
            "global" => RuleScope::Global,
            "connection" => RuleScope::Connection(row.scope_id),
            "database" => RuleScope::Database(row.scope_id),
            other => return Err(format!("POLICY_SCOPE_INVALID: {other}")),
        };
        documents.push((scope, row.version, row.document_json));
    }
    CompiledPolicy::compile(&documents)
}

fn validate(document: &PolicyDocument) -> Result<(), String> {
    for rule in &document.rules {
        if rule.id.trim().is_empty() {
            return Err("POLICY_RULE_ID_REQUIRED".to_string());
        }
        if rule.message.trim().is_empty() {
            return Err(format!("POLICY_RULE_MESSAGE_REQUIRED: {}", rule.id));
        }
    }
    Ok(())
}

fn scope_rank(scope: &RuleScope) -> u8 {
    match scope {
        RuleScope::Global => 0,
        RuleScope::Connection(_) => 1,
        RuleScope::Database(_) => 2,
    }
}

fn bundle_hash(documents: &[ScopedPolicy]) -> String {
    let canonical = serde_json::json!({
        "engine": ENGINE_VERSION,
        "builtins": builtin_rules().iter().map(|rule| serde_json::json!({
            "id": rule.id,
            "priority": rule.priority,
            "effect": rule.effect.as_str(),
            "match": rule.rule_match,
            "message": rule.message,
        })).collect::<Vec<_>>(),
        "documents": documents.iter().map(|scoped| serde_json::json!({
            "scope": scoped.scope,
            "version": scoped.version,
            "document": scoped.document,
        })).collect::<Vec<_>>(),
    });
    sha256_hex(canonical.to_string().as_bytes())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::connection::DatabaseType;

    fn document(json: &str) -> String {
        json.to_string()
    }

    #[test]
    fn an_empty_set_is_exactly_the_builtins_and_has_a_stable_hash() {
        let first = CompiledPolicy::builtin_only();
        let second = CompiledPolicy::builtin_only();
        assert_eq!(first.bundle_hash(), second.bundle_hash());
        assert_eq!(first.rules().len(), builtin_rules().len());
    }

    #[test]
    fn a_published_rule_tightens_and_changes_the_bundle_hash() {
        let base = CompiledPolicy::builtin_only();
        let json = document(
            r#"{"rules":[{"id":"conn.deny-updates","priority":200,"action":"block","message":"updates are blocked","match":{"statement_types":["dml"]}}]}"#,
        );
        let compiled = CompiledPolicy::compile(&[(RuleScope::Connection("conn".into()), 1, json)]).unwrap();
        assert_ne!(base.bundle_hash(), compiled.bundle_hash());
        let decision =
            compiled.decide("conn", "app", DatabaseType::Postgres, "UPDATE users SET a = 1 WHERE id = 2", false);
        assert_eq!(decision.effect, PolicyEffect::Block);
        assert_eq!(decision.rule_id.as_deref(), Some("conn.deny-updates"));
        // Another connection is unaffected.
        let other =
            compiled.decide("other", "app", DatabaseType::Postgres, "UPDATE users SET a = 1 WHERE id = 2", false);
        assert_eq!(other.effect, PolicyEffect::Allow);
    }

    #[test]
    fn a_stored_rule_can_disable_a_builtin_by_reusing_its_id() {
        let json = document(
            r#"{"rules":[{"id":"global.ddl.warn","enabled":false,"priority":5,"action":"warn","message":"disabled"}]}"#,
        );
        let compiled = CompiledPolicy::compile(&[(RuleScope::Global, 1, json)]).unwrap();
        let decision = compiled.decide("conn", "app", DatabaseType::Postgres, "ALTER TABLE t ADD COLUMN c int", false);
        assert_eq!(decision.effect, PolicyEffect::Allow);
    }

    #[test]
    fn an_invalid_document_is_rejected() {
        let missing_message = document(r#"{"rules":[{"id":"x","priority":1,"action":"block","message":""}]}"#);
        assert!(CompiledPolicy::compile(&[(RuleScope::Global, 1, missing_message)]).is_err());
        assert!(CompiledPolicy::compile(&[(RuleScope::Global, 1, "{not json".to_string())]).is_err());
    }

    #[test]
    fn the_narrower_scope_wins_when_both_define_the_same_rule_id() {
        let global = document(
            r#"{"rules":[{"id":"shared","priority":10,"action":"warn","message":"global","match":{"statement_types":["dml"]}}]}"#,
        );
        let connection = document(
            r#"{"rules":[{"id":"shared","priority":10,"action":"block","message":"connection","match":{"statement_types":["dml"]}}]}"#,
        );
        let compiled = CompiledPolicy::compile(&[
            (RuleScope::Global, 1, global),
            (RuleScope::Connection("conn".into()), 1, connection),
        ])
        .unwrap();
        let decision = compiled.decide("conn", "app", DatabaseType::Postgres, "UPDATE t SET a = 1 WHERE id = 2", false);
        assert_eq!(decision.effect, PolicyEffect::Block);
    }
}
