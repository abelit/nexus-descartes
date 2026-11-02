//! High-risk SQL rules and their evaluation.
//!
//! Two sources feed one compiled rule set: the code-defined built-ins (a safety
//! floor that cannot be deleted) and published policy documents scoped to
//! global, connection, or database. Evaluation takes the strictest effect, so a
//! narrower scope can only tighten a broader one — an explicit `allow` can
//! never override a parent `block`.
//!
//! Every compiled rule set carries a `policy_bundle_hash`; audit events and
//! approvals bind to it, so a policy change invalidates outstanding approvals.

use serde::{Deserialize, Serialize};

use crate::models::connection::DatabaseType;
use crate::sql_risk::{classify_sql_risk_for_database, is_dangerous_sql_for_database, SqlRisk};

/// Effects ordered from weakest to strongest: `max()` picks the strictest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyEffect {
    Allow,
    Warn,
    RequireApproval,
    Block,
}

impl PolicyEffect {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Warn => "warn",
            Self::RequireApproval => "require_approval",
            Self::Block => "block",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "allow" => Some(Self::Allow),
            "warn" => Some(Self::Warn),
            "require_approval" => Some(Self::RequireApproval),
            "block" => Some(Self::Block),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleHit {
    pub rule_id: String,
    pub effect: PolicyEffect,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyDecision {
    pub effect: PolicyEffect,
    pub rule_id: Option<String>,
    pub reason: String,
    pub matched: Vec<RuleHit>,
    pub policy_bundle_hash: String,
}

impl PolicyDecision {
    pub fn allowed(bundle_hash: &str) -> Self {
        Self {
            effect: PolicyEffect::Allow,
            rule_id: None,
            reason: "no rule matched".to_string(),
            matched: Vec::new(),
            policy_bundle_hash: bundle_hash.to_string(),
        }
    }
}

/// Where a rule applies. Rules from broader scopes are inherited by narrower
/// ones; the strictest matched effect wins across all of them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type", content = "id")]
pub enum RuleScope {
    Global,
    Connection(String),
    Database(String),
}

/// Match conditions. Empty vectors mean "any".
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleMatch {
    #[serde(default)]
    pub statement_types: Vec<String>,
    #[serde(default)]
    pub production_only: bool,
    /// `Some(true)` requires a bounding condition; `Some(false)` requires its
    /// absence.
    #[serde(default)]
    pub requires_where: Option<bool>,
    #[serde(default)]
    pub unbounded_only: bool,
    /// Database-name globs (`*` allowed). Empty means any database.
    #[serde(default)]
    pub databases: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub id: String,
    pub enabled: bool,
    pub priority: i32,
    pub effect: PolicyEffect,
    pub rule_match: RuleMatch,
    pub message: String,
    pub scope: RuleScope,
    /// Built-in rules cannot be deleted, only overridden by id in a stored
    /// document.
    pub builtin: bool,
}

pub struct RuleContext<'a> {
    pub connection_id: &'a str,
    pub database: &'a str,
    pub db_type: DatabaseType,
    pub sql: &'a str,
    pub is_production: bool,
}

fn risk(ctx: &RuleContext<'_>) -> SqlRisk {
    classify_sql_risk_for_database(ctx.sql, ctx.db_type).unwrap_or(SqlRisk::Write)
}

fn normalized(sql: &str) -> String {
    sql.to_ascii_uppercase()
}

fn is_truncate(sql: &str) -> bool {
    normalized(sql).trim_start().starts_with("TRUNCATE")
}

fn is_privilege_change(sql: &str) -> bool {
    let trimmed = normalized(sql);
    let trimmed = trimmed.trim_start();
    trimmed.starts_with("GRANT ") || trimmed.starts_with("REVOKE ") || trimmed.starts_with("CREATE USER")
}

fn statement_type(ctx: &RuleContext<'_>) -> &'static str {
    if is_truncate(ctx.sql) {
        return "truncate";
    }
    if is_privilege_change(ctx.sql) {
        return "privilege";
    }
    match risk(ctx) {
        SqlRisk::ReadOnly => "select",
        SqlRisk::Write => "dml",
        SqlRisk::Ddl => "ddl",
        SqlRisk::Transaction => "transaction",
    }
}

fn like(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return value.starts_with(prefix);
    }
    pattern.eq_ignore_ascii_case(value)
}

fn scope_applies(rule: &Rule, ctx: &RuleContext<'_>) -> bool {
    match &rule.scope {
        RuleScope::Global => true,
        RuleScope::Connection(connection_id) => connection_id == ctx.connection_id,
        RuleScope::Database(scope) => match scope.split_once("::") {
            // A database scope may pin both the connection and the database
            // (`<connection_id>::<database>`); a plain value matches the
            // database name on any connection.
            Some((connection_id, database)) => connection_id == ctx.connection_id && like(database, ctx.database),
            None => like(scope, ctx.database),
        },
    }
}

fn matches(rule: &Rule, ctx: &RuleContext<'_>) -> bool {
    if !rule.enabled || !scope_applies(rule, ctx) {
        return false;
    }
    let rule_match = &rule.rule_match;
    if rule_match.production_only && !ctx.is_production {
        return false;
    }
    if !rule_match.statement_types.is_empty()
        && !rule_match.statement_types.iter().any(|r#type| r#type == statement_type(ctx))
    {
        return false;
    }
    if !rule_match.databases.is_empty() && !rule_match.databases.iter().any(|pattern| like(pattern, ctx.database)) {
        return false;
    }
    let dangerous = is_dangerous_sql_for_database(ctx.sql, ctx.db_type);
    if rule_match.unbounded_only && !dangerous {
        return false;
    }
    match rule_match.requires_where {
        Some(true) if dangerous => return false,
        Some(false) if !dangerous => return false,
        _ => {}
    }
    true
}

/// Code-defined safety floor. Each rule is global; stored documents can add
/// rules or override a built-in by reusing its id in a narrower scope.
pub fn builtin_rules() -> Vec<Rule> {
    let rule = |id: &str, priority: i32, effect: PolicyEffect, rule_match: RuleMatch, message: &str| Rule {
        id: id.to_string(),
        enabled: true,
        priority,
        effect,
        rule_match,
        message: message.to_string(),
        scope: RuleScope::Global,
        builtin: true,
    };
    vec![
        rule(
            "prod.ddl.approval",
            100,
            PolicyEffect::RequireApproval,
            RuleMatch { statement_types: vec!["ddl".into()], production_only: true, ..Default::default() },
            "DDL on a production connection requires approval",
        ),
        rule(
            "prod.dml.no_where.block",
            110,
            PolicyEffect::Block,
            RuleMatch {
                statement_types: vec!["dml".into()],
                production_only: true,
                unbounded_only: true,
                ..Default::default()
            },
            "An unbounded write on a production connection is blocked",
        ),
        rule(
            "prod.truncate.approval",
            105,
            PolicyEffect::RequireApproval,
            RuleMatch { statement_types: vec!["truncate".into()], production_only: true, ..Default::default() },
            "TRUNCATE on a production connection requires approval",
        ),
        rule(
            "prod.privilege.approval",
            105,
            PolicyEffect::RequireApproval,
            RuleMatch { statement_types: vec!["privilege".into()], production_only: true, ..Default::default() },
            "Privilege changes on a production connection require approval",
        ),
        rule(
            "global.no_where.warn",
            10,
            PolicyEffect::Warn,
            RuleMatch { statement_types: vec!["dml".into()], unbounded_only: true, ..Default::default() },
            "This statement has no bounding condition",
        ),
        rule(
            "global.ddl.warn",
            5,
            PolicyEffect::Warn,
            RuleMatch { statement_types: vec!["ddl".into()], ..Default::default() },
            "Schema changes cannot be rolled back on every backend",
        ),
    ]
}

/// Strictest effect wins: `block` > `require_approval` > `warn` > `allow`.
pub fn evaluate(rules: &[Rule], context: &RuleContext<'_>, bundle_hash: &str) -> PolicyDecision {
    let mut ordered: Vec<&Rule> = rules.iter().collect();
    ordered.sort_by(|left, right| {
        right
            .priority
            .cmp(&left.priority)
            .then_with(|| left.id.cmp(&right.id))
            .then_with(|| scope_rank(&left.scope).cmp(&scope_rank(&right.scope)))
    });

    let mut matched = Vec::new();
    for rule in ordered {
        if matches(rule, context) {
            matched.push(RuleHit { rule_id: rule.id.clone(), effect: rule.effect, reason: rule.message.clone() });
        }
    }

    let Some(strictest) = matched
        .iter()
        .max_by(|left, right| left.effect.cmp(&right.effect).then_with(|| right.rule_id.cmp(&left.rule_id)))
    else {
        return PolicyDecision::allowed(bundle_hash);
    };
    PolicyDecision {
        effect: strictest.effect,
        rule_id: Some(strictest.rule_id.clone()),
        reason: strictest.reason.clone(),
        matched,
        policy_bundle_hash: bundle_hash.to_string(),
    }
}

fn scope_rank(scope: &RuleScope) -> u8 {
    match scope {
        RuleScope::Global => 0,
        RuleScope::Connection(_) => 1,
        RuleScope::Database(_) => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(sql: &str, is_production: bool) -> RuleContext<'_> {
        RuleContext { connection_id: "conn", database: "app", db_type: DatabaseType::Postgres, sql, is_production }
    }

    fn decision(sql: &str, is_production: bool) -> PolicyDecision {
        evaluate(&builtin_rules(), &context(sql, is_production), "bundle")
    }

    #[test]
    fn a_select_is_allowed() {
        assert_eq!(decision("SELECT id FROM users WHERE id = 1", true).effect, PolicyEffect::Allow);
    }

    #[test]
    fn production_ddl_requires_approval() {
        let decision = decision("ALTER TABLE users ADD COLUMN age int", true);
        assert_eq!(decision.effect, PolicyEffect::RequireApproval);
        assert_eq!(decision.rule_id.as_deref(), Some("prod.ddl.approval"));
        assert_eq!(decision.policy_bundle_hash, "bundle");
    }

    #[test]
    fn the_same_ddl_outside_production_only_warns() {
        let decision = decision("ALTER TABLE users ADD COLUMN age int", false);
        assert_eq!(decision.effect, PolicyEffect::Warn);
        assert_eq!(decision.rule_id.as_deref(), Some("global.ddl.warn"));
    }

    #[test]
    fn an_unbounded_delete_on_production_is_blocked() {
        let decision = decision("DELETE FROM users", true);
        assert_eq!(decision.effect, PolicyEffect::Block);
        assert_eq!(decision.rule_id.as_deref(), Some("prod.dml.no_where.block"));
    }

    #[test]
    fn a_bounded_delete_is_allowed() {
        assert_eq!(decision("DELETE FROM users WHERE id = 1", true).effect, PolicyEffect::Allow);
    }

    #[test]
    fn truncate_and_privilege_changes_require_approval_on_production() {
        assert_eq!(decision("TRUNCATE TABLE users", true).effect, PolicyEffect::RequireApproval);
        assert_eq!(decision("GRANT SELECT ON users TO app", true).effect, PolicyEffect::RequireApproval);
    }

    #[test]
    fn the_strictest_effect_wins_and_every_match_is_reported() {
        let decision = decision("UPDATE users SET name = 'x'", true);
        assert_eq!(decision.effect, PolicyEffect::Block);
        assert!(decision.matched.len() >= 2);
    }

    #[test]
    fn scoped_rules_only_apply_to_their_scope() {
        let mut rules = builtin_rules();
        rules.push(Rule {
            id: "conn.block-delete".into(),
            enabled: true,
            priority: 120,
            effect: PolicyEffect::Block,
            rule_match: RuleMatch { statement_types: vec!["dml".into()], ..Default::default() },
            message: "deletes are blocked on this connection".into(),
            scope: RuleScope::Connection("conn".into()),
            builtin: false,
        });
        let on_conn = evaluate(&rules, &context("DELETE FROM users WHERE id = 1", false), "b");
        assert_eq!(on_conn.effect, PolicyEffect::Block);
        let other_conn = evaluate(
            &rules,
            &RuleContext { connection_id: "other", ..context("DELETE FROM users WHERE id = 1", false) },
            "b",
        );
        assert_eq!(other_conn.effect, PolicyEffect::Allow);
    }

    #[test]
    fn a_database_scope_can_pin_the_connection() {
        let rules = vec![Rule {
            id: "db.pinned".into(),
            enabled: true,
            priority: 1,
            effect: PolicyEffect::Block,
            rule_match: RuleMatch { statement_types: vec!["select".into()], ..Default::default() },
            message: "pinned".into(),
            scope: RuleScope::Database("conn::app".into()),
            builtin: false,
        }];
        assert_eq!(evaluate(&rules, &context("SELECT 1", false), "b").effect, PolicyEffect::Block);
        let other_connection =
            evaluate(&rules, &RuleContext { connection_id: "other", ..context("SELECT 1", false) }, "b");
        assert_eq!(other_connection.effect, PolicyEffect::Allow);
    }

    #[test]
    fn a_disabled_builtin_does_not_fire() {
        let mut rules = builtin_rules();
        for rule in &mut rules {
            if rule.id == "global.ddl.warn" {
                rule.enabled = false;
            }
        }
        assert_eq!(
            evaluate(&rules, &context("ALTER TABLE t ADD COLUMN c int", false), "b").effect,
            PolicyEffect::Allow
        );
    }

    #[test]
    fn database_globs_match_prefixes_and_wildcards() {
        let rules = vec![Rule {
            id: "db.block".into(),
            enabled: true,
            priority: 1,
            effect: PolicyEffect::Block,
            rule_match: RuleMatch { databases: vec!["prod_*".into()], ..Default::default() },
            message: "blocked".into(),
            scope: RuleScope::Global,
            builtin: false,
        }];
        assert_eq!(
            evaluate(&rules, &RuleContext { database: "prod_billing", ..context("SELECT 1", false) }, "b").effect,
            PolicyEffect::Block
        );
        assert_eq!(
            evaluate(&rules, &RuleContext { database: "staging", ..context("SELECT 1", false) }, "b").effect,
            PolicyEffect::Allow
        );
    }
}
