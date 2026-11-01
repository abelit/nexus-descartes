//! Built-in high-risk SQL rules.
//!
//! This is the first, code-defined rule set. Policy documents stored per scope
//! (with versions and a bundle hash) will replace it incrementally; the
//! evaluation contract — strictest effect wins, `block` cannot be overridden —
//! is what the rest of the gateway relies on.

use crate::models::connection::DatabaseType;
use crate::sql_risk::{classify_sql_risk_for_database, is_dangerous_sql_for_database, SqlRisk};

/// Effects ordered from weakest to strongest: `max()` picks the strictest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
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
}

impl PolicyDecision {
    pub fn allowed() -> Self {
        Self { effect: PolicyEffect::Allow, rule_id: None, reason: "no rule matched".to_string(), matched: Vec::new() }
    }
}

#[derive(Clone, Debug)]
pub struct Rule {
    pub id: &'static str,
    pub priority: i32,
    pub effect: PolicyEffect,
    pub matcher: Matcher,
    pub message: &'static str,
}

#[derive(Clone, Copy, Debug)]
pub enum Matcher {
    DdlOnProduction,
    UnboundedWriteOnProduction,
    UnboundedWriteAnywhere,
    TruncateOnProduction,
    PrivilegeChangeOnProduction,
    DdlAnywhere,
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

fn matches(matcher: Matcher, ctx: &RuleContext<'_>) -> bool {
    let risk = risk(ctx);
    match matcher {
        Matcher::DdlOnProduction => ctx.is_production && risk == SqlRisk::Ddl,
        Matcher::UnboundedWriteOnProduction => {
            ctx.is_production && risk == SqlRisk::Write && is_dangerous_sql_for_database(ctx.sql, ctx.db_type)
        }
        Matcher::UnboundedWriteAnywhere => {
            risk == SqlRisk::Write && is_dangerous_sql_for_database(ctx.sql, ctx.db_type)
        }
        Matcher::TruncateOnProduction => ctx.is_production && is_truncate(ctx.sql),
        Matcher::PrivilegeChangeOnProduction => ctx.is_production && is_privilege_change(ctx.sql),
        Matcher::DdlAnywhere => risk == SqlRisk::Ddl,
    }
}

fn normalized(sql: &str) -> String {
    sql.to_ascii_uppercase()
}

fn is_truncate(sql: &str) -> bool {
    normalized(sql).trim_start().starts_with("TRUNCATE")
}

fn is_privilege_change(sql: &str) -> bool {
    let upper = normalized(sql);
    let trimmed = upper.trim_start();
    trimmed.starts_with("GRANT ") || trimmed.starts_with("REVOKE ") || trimmed.starts_with("CREATE USER")
}

/// Code-defined rules, evaluated before stored policies exist. Ordering here is
/// documentation only: evaluation sorts by priority, then id.
pub fn builtin_rules() -> Vec<Rule> {
    vec![
        Rule {
            id: "prod.ddl.approval",
            priority: 100,
            effect: PolicyEffect::RequireApproval,
            matcher: Matcher::DdlOnProduction,
            message: "DDL on a production connection requires approval",
        },
        Rule {
            id: "prod.dml.no_where.block",
            priority: 110,
            effect: PolicyEffect::Block,
            matcher: Matcher::UnboundedWriteOnProduction,
            message: "An unbounded write on a production connection is blocked",
        },
        Rule {
            id: "prod.truncate.approval",
            priority: 105,
            effect: PolicyEffect::RequireApproval,
            matcher: Matcher::TruncateOnProduction,
            message: "TRUNCATE on a production connection requires approval",
        },
        Rule {
            id: "prod.privilege.approval",
            priority: 105,
            effect: PolicyEffect::RequireApproval,
            matcher: Matcher::PrivilegeChangeOnProduction,
            message: "Privilege changes on a production connection require approval",
        },
        Rule {
            id: "global.no_where.warn",
            priority: 10,
            effect: PolicyEffect::Warn,
            matcher: Matcher::UnboundedWriteAnywhere,
            message: "This statement has no bounding condition",
        },
        Rule {
            id: "global.ddl.warn",
            priority: 5,
            effect: PolicyEffect::Warn,
            matcher: Matcher::DdlAnywhere,
            message: "Schema changes cannot be rolled back on every backend",
        },
    ]
}

/// Strictest effect wins: `block` > `require_approval` > `warn` > `allow`.
pub fn evaluate(rules: &[Rule], context: &RuleContext<'_>) -> PolicyDecision {
    let mut ordered = rules.to_vec();
    ordered.sort_by(|left, right| right.priority.cmp(&left.priority).then_with(|| left.id.cmp(right.id)));

    let mut matched = Vec::new();
    for rule in &ordered {
        if matches(rule.matcher, context) {
            matched.push(RuleHit {
                rule_id: rule.id.to_string(),
                effect: rule.effect,
                reason: rule.message.to_string(),
            });
        }
    }

    let Some(strictest) = matched
        .iter()
        .max_by(|left, right| left.effect.cmp(&right.effect).then_with(|| right.rule_id.cmp(&left.rule_id)))
    else {
        return PolicyDecision::allowed();
    };
    PolicyDecision {
        effect: strictest.effect,
        rule_id: Some(strictest.rule_id.clone()),
        reason: strictest.reason.clone(),
        matched,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(sql: &str, is_production: bool) -> RuleContext<'_> {
        RuleContext { connection_id: "conn", database: "app", db_type: DatabaseType::Postgres, sql, is_production }
    }

    fn decision(sql: &str, is_production: bool) -> PolicyDecision {
        evaluate(&builtin_rules(), &context(sql, is_production))
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
    fn truncate_requires_approval_on_production() {
        let decision = decision("TRUNCATE TABLE users", true);
        assert_eq!(decision.effect, PolicyEffect::RequireApproval);
        assert!(decision.matched.iter().any(|hit| hit.rule_id == "prod.truncate.approval"));
    }

    #[test]
    fn privilege_changes_require_approval_on_production() {
        let decision = decision("GRANT SELECT ON users TO app", true);
        assert_eq!(decision.effect, PolicyEffect::RequireApproval);
        assert!(decision.matched.iter().any(|hit| hit.rule_id == "prod.privilege.approval"));
    }

    #[test]
    fn the_strictest_effect_wins() {
        // Unbounded write + production: the block rule outranks the warn rule
        // and approval rules.
        let decision = decision("UPDATE users SET name = 'x'", true);
        assert_eq!(decision.effect, PolicyEffect::Block);
        assert!(decision.matched.len() >= 2, "every matching rule is reported");
    }
}
