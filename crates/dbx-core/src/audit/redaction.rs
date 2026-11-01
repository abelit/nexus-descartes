//! How much of a statement is retained in the audit log.
//!
//! `full` is the default and keeps the statement verbatim, which is what makes
//! the audit useful for forensics. It still masks credential literals by
//! default (`DBX_AUDIT_MASK_CREDENTIALS`), because a password embedded in
//! `CREATE USER ... IDENTIFIED BY` or in a connection string is not evidence
//! about the operation, it is a secret leak into the audit database.
//!
//! The mode is recorded on every event, so a reader never has to guess whether
//! a missing statement means "digest only" or "the statement was empty".

use std::sync::LazyLock;

use regex::Regex;

/// `DBX_AUDIT_SQL_MODE`
const ENV_SQL_MODE: &str = "DBX_AUDIT_SQL_MODE";
/// `DBX_AUDIT_MASK_CREDENTIALS` (default on)
const ENV_MASK_CREDENTIALS: &str = "DBX_AUDIT_MASK_CREDENTIALS";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SqlRetentionMode {
    /// Keep the statement as written (credentials still masked by default).
    Full,
    /// Keep the statement with credential literals always masked.
    Redacted,
    /// Keep only the digest and fingerprint.
    Digest,
}

impl SqlRetentionMode {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "full" | "raw" => Some(Self::Full),
            "redacted" | "masked" => Some(Self::Redacted),
            "digest" | "hash" => Some(Self::Digest),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Redacted => "redacted",
            Self::Digest => "digest",
        }
    }
}

/// The SQL text that will be stored, plus how it was derived.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetainedSql {
    pub text: Option<String>,
    pub redaction_mode: &'static str,
    pub credentials_masked: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct SqlRetention {
    mode: SqlRetentionMode,
    mask_credentials: bool,
}

impl Default for SqlRetention {
    fn default() -> Self {
        Self { mode: SqlRetentionMode::Full, mask_credentials: true }
    }
}

impl SqlRetention {
    pub fn new(mode: SqlRetentionMode, mask_credentials: bool) -> Self {
        Self { mode, mask_credentials }
    }

    /// Process-wide policy, read once from the environment.
    pub fn for_process() -> &'static Self {
        static RETENTION: LazyLock<SqlRetention> = LazyLock::new(SqlRetention::from_env);
        &RETENTION
    }

    pub fn from_env() -> Self {
        let mode = match std::env::var(ENV_SQL_MODE) {
            Ok(value) => SqlRetentionMode::parse(&value).unwrap_or_else(|| {
                // Never silently downgrade to "digest" or "off" on a typo:
                // the confirmed default is the most useful mode.
                log::warn!("[audit] unknown {ENV_SQL_MODE}={value:?}; falling back to full");
                SqlRetentionMode::Full
            }),
            Err(_) => SqlRetentionMode::Full,
        };
        let mask_credentials = match std::env::var(ENV_MASK_CREDENTIALS) {
            Ok(value) => !matches!(value.trim().to_ascii_lowercase().as_str(), "0" | "false" | "no" | "off"),
            Err(_) => true,
        };
        Self { mode, mask_credentials }
    }

    pub fn mode(&self) -> SqlRetentionMode {
        self.mode
    }

    pub fn masks_credentials(&self) -> bool {
        self.mask_credentials || self.mode == SqlRetentionMode::Redacted
    }

    pub fn retain(&self, sql: &str) -> RetainedSql {
        match self.mode {
            SqlRetentionMode::Digest => {
                RetainedSql { text: None, redaction_mode: self.mode.as_str(), credentials_masked: false }
            }
            SqlRetentionMode::Redacted => {
                let (text, changed) = mask_credentials(sql);
                let _ = changed;
                RetainedSql { text: Some(text), redaction_mode: self.mode.as_str(), credentials_masked: true }
            }
            SqlRetentionMode::Full => {
                if self.mask_credentials {
                    let (text, changed) = mask_credentials(sql);
                    RetainedSql { text: Some(text), redaction_mode: self.mode.as_str(), credentials_masked: changed }
                } else {
                    RetainedSql {
                        text: Some(sql.to_string()),
                        redaction_mode: self.mode.as_str(),
                        credentials_masked: false,
                    }
                }
            }
        }
    }
}

/// Replaces credential literals in `sql`, returning the masked text and
/// whether anything changed.
pub fn mask_credentials(sql: &str) -> (String, bool) {
    let mut text = sql.to_string();
    for (pattern, replacement) in MASKS.iter() {
        text = pattern.replace_all(&text, replacement.as_str()).into_owned();
    }
    let changed = text != sql;
    (text, changed)
}

/// Ordered so that more specific forms run before the generic ones.
static MASKS: LazyLock<Vec<(Regex, String)>> = LazyLock::new(|| {
    let entries: &[(&str, &str)] = &[
        // CREATE/ALTER USER ... IDENTIFIED [WITH plugin] BY '<password>'
        (r"(?i)(\bIDENTIFIED\s+(?:WITH\s+\S+\s+)?BY\s+)'(?:[^']|'')*'", "${1}'***'"),
        // SET PASSWORD [FOR user] = '<password>'
        (r#"(?i)(\bSET\s+PASSWORD\b[^;'"=]*?=\s*)'(?:[^']|'')*'"#, "${1}'***'"),
        // PASSWORD/TOKEN/SECRET/etc. followed by a quoted literal
        (
            r#"(?i)(\b(?:PASSWORD|PASSWD|PWD|TOKEN|SECRET|API[_-]?KEY|ACCESS[_-]?KEY|SECRET[_-]?KEY|PRIVATE[_-]?KEY)\s*(?:=|:=|TO)\s*)'[^']*'"#,
            "${1}'***'",
        ),
        // The same keywords followed by an unquoted literal
        (
            r#"(?i)(\b(?:PASSWORD|PASSWD|PWD|TOKEN|SECRET|API[_-]?KEY|ACCESS[_-]?KEY|SECRET[_-]?KEY|PRIVATE[_-]?KEY)\s*(?:=|:=)\s*)([^\s,;'"()]+)"#,
            "${1}***",
        ),
        // scheme://user:password@host  (Postgres/MySQL/Mongo/Redis URIs)
        (r"(?i)(\b[a-z][a-z0-9+.-]*://[^/\s:@]*:)([^@\s/]+)(@)", "${1}***${3}"),
        // ...?password=... / &access_key=... in connection strings
        (r#"(?i)([?&;](?:password|pwd|passwd|access[_-]?key|secret[_-]?key|token)=)([^&\s;'"]+)"#, "${1}***"),
        // A whole Redis AUTH statement is a credential.
        (r"(?is)^(\s*AUTH\s+).*$", "${1}***"),
    ];
    entries
        .iter()
        .map(|(pattern, replacement)| {
            (
                Regex::new(pattern).unwrap_or_else(|error| panic!("audit mask regex {pattern}: {error}")),
                (*replacement).to_string(),
            )
        })
        .collect()
});

/// Literal-normalized statement for grouping identical shapes.
///
/// The digest answers "is this the same statement?", the fingerprint answers
/// "how often did this kind of statement run?".
pub fn sql_fingerprint(sql: &str) -> String {
    let literals = LITERAL_PATTERN.replace_all(sql, "?");
    let numbers = NUMBER_PATTERN.replace_all(&literals, "${1}?");
    numbers.split_whitespace().collect::<Vec<_>>().join(" ")
}

static LITERAL_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"'(?:[^'\\]|\\.|'')*'").expect("audit literal pattern"));
static NUMBER_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    // Keep identifiers like `t1` intact; only standalone numbers become `?`.
    Regex::new(r"(?m)(^|[\s(,=<>+\-*/])\d+(?:\.\d+)?").expect("audit number pattern")
});

#[cfg(test)]
mod tests {
    use super::*;

    fn mode(value: &str) -> SqlRetentionMode {
        SqlRetentionMode::parse(value).expect("mode")
    }

    #[test]
    fn a_plain_query_is_left_alone() {
        let sql = "SELECT id, name FROM users WHERE id = 7";
        let (masked, changed) = mask_credentials(sql);
        assert!(!changed);
        assert_eq!(masked, sql);
    }

    #[test]
    fn create_user_password_is_masked() {
        let (masked, changed) =
            mask_credentials("CREATE USER 'app'@'%' IDENTIFIED WITH mysql_native_password BY 'hunter2'");
        assert!(changed);
        assert!(!masked.contains("hunter2"));
        assert!(masked.contains("'***'"));
    }

    #[test]
    fn postgres_set_password_is_masked() {
        let (masked, changed) = mask_credentials("ALTER USER app SET PASSWORD = 'hunter2'");
        assert!(changed);
        assert!(!masked.contains("hunter2"), "{masked}");
    }

    #[test]
    fn a_connection_uri_password_is_masked() {
        let (masked, changed) = mask_credentials("connect postgres://app:hunter2@db.internal:5432/app");
        assert!(changed);
        assert!(!masked.contains("hunter2"));
        assert_eq!(masked, "connect postgres://app:***@db.internal:5432/app");
    }

    #[test]
    fn a_redis_auth_statement_is_fully_masked() {
        let (masked, _) = mask_credentials("AUTH hunter2");
        assert_eq!(masked.trim(), "AUTH ***");
    }

    #[test]
    fn digest_mode_keeps_no_text() {
        let retention = SqlRetention::new(SqlRetentionMode::Digest, true);
        let retained = retention.retain("SELECT 1");
        assert_eq!(retained.text, None);
        assert_eq!(retained.redaction_mode, "digest");
    }

    #[test]
    fn full_mode_with_masking_disabled_keeps_the_statement() {
        let retention = SqlRetention::new(SqlRetentionMode::Full, false);
        let sql = "ALTER USER app SET PASSWORD = 'hunter2'";
        let retained = retention.retain(sql);
        assert_eq!(retained.text.as_deref(), Some(sql));
        assert!(!retained.credentials_masked);
        assert_eq!(retained.redaction_mode, "full");
    }

    #[test]
    fn redacted_mode_is_always_masked() {
        let retention = SqlRetention::new(SqlRetentionMode::Redacted, false);
        let retained = retention.retain("ALTER USER app SET PASSWORD = 'hunter2'");
        assert!(!retained.text.unwrap().contains("hunter2"));
        assert!(retained.credentials_masked);
        assert_eq!(retained.redaction_mode, "redacted");
    }

    #[test]
    fn fingerprint_normalizes_literals_but_not_identifiers() {
        assert_eq!(sql_fingerprint("SELECT * FROM users WHERE id = 42"), "SELECT * FROM users WHERE id = ?");
        assert_eq!(
            sql_fingerprint("SELECT * FROM users WHERE name = 'bob'"),
            sql_fingerprint("SELECT * FROM users WHERE name = 'alice'")
        );
        assert_ne!(sql_fingerprint("SELECT t1 FROM a"), sql_fingerprint("SELECT t2 FROM a"));
    }

    #[test]
    fn unknown_mode_names_are_rejected() {
        assert!(SqlRetentionMode::parse("off").is_none());
        assert!(SqlRetentionMode::parse("debug").is_none());
        assert_eq!(mode("DIGEST"), SqlRetentionMode::Digest);
    }
}
