use super::{params, params_from_iter, OptionalExtension, Storage, TransactionBehavior};
use crate::audit::{
    Actor, ActorKind, AuditChainHead, AuditChainReport, AuditCheckpoint, AuditCheckpointReport, AuditCount,
    AuditDecision, AuditEvent, AuditEventInsert, AuditOperation, AuditOutcome, AuditPage, AuditQuery, AuditSource,
    AuditStats,
};
use chrono::Utc;
use rusqlite::types::Value;
use sha2::{Digest, Sha256};

const CHAIN_ID: &str = "default";
/// Frozen legacy canonical form: `occurred_at` (text) and the chain position
/// are hashed, but not `occurred_at_ms` and not the scheme name itself.
const HASH_SCHEME_V1: &str = "sha256-v1";
/// Current canonical form: adds `occurred_at_ms` and `hash_scheme` to the
/// hashed bytes, so a verifier cannot silently reinterpret a row.
const HASH_SCHEME_V2: &str = "sha256-v2";
/// Scheme used for every newly written event.
const CURRENT_HASH_SCHEME: &str = HASH_SCHEME_V2;
const MAX_QUERY_LIMIT: usize = 500;
const DEFAULT_QUERY_LIMIT: usize = 100;

const EVENT_COLUMNS: &str = "seq, event_id, occurred_at, occurred_at_ms, actor_id, actor_display_name, \
actor_kind, actor_roles_json, tenant_id, session_id, auth_method, source, client_ip, user_agent, \
request_id, connection_id, connection_name, database, schema_name, operation, sql_text, sql_digest, \
risk_level, decision, rule_id, policy_version, approval_id, outcome, error_code, error_message, \
affected_rows, duration_ms, details_json, prev_hash, event_hash, event_type, resource_type, \
resource_id, table_name, statement_index, execution_id, request_method, request_path, http_status, \
redaction_mode, sql_fingerprint, matched_rule_ids_json, policy_bundle_hash, actor_verified, \
on_behalf_of, delegated_by";

/// Columns added after the first shipped schema. Kept in one list so the
/// `CREATE TABLE` shape and the `ALTER TABLE` migration cannot drift.
const EXTENDED_COLUMNS: &[(&str, &str)] = &[
    ("event_type", "TEXT NOT NULL DEFAULT 'domain'"),
    ("resource_type", "TEXT"),
    ("resource_id", "TEXT"),
    ("table_name", "TEXT"),
    ("statement_index", "INTEGER"),
    ("execution_id", "TEXT"),
    ("request_method", "TEXT"),
    ("request_path", "TEXT"),
    ("http_status", "INTEGER"),
    ("redaction_mode", "TEXT"),
    ("sql_fingerprint", "TEXT"),
    ("matched_rule_ids_json", "TEXT NOT NULL DEFAULT '[]'"),
    ("policy_bundle_hash", "TEXT"),
    ("actor_verified", "INTEGER NOT NULL DEFAULT 0"),
    ("on_behalf_of", "TEXT"),
    ("delegated_by", "TEXT"),
];

/// Creates the audit tables, indexes, and append-only triggers. Called from
/// `Storage::init_schema` on every open, so every statement is idempotent.
pub(super) fn ensure_audit_schema_sync(conn: &rusqlite::Connection) -> Result<(), String> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS audit_events (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL UNIQUE,
            occurred_at TEXT NOT NULL,
            occurred_at_ms INTEGER NOT NULL,
            actor_id TEXT NOT NULL,
            actor_display_name TEXT NOT NULL DEFAULT '',
            actor_kind TEXT NOT NULL,
            actor_roles_json TEXT NOT NULL DEFAULT '[]',
            tenant_id TEXT,
            session_id TEXT,
            auth_method TEXT NOT NULL DEFAULT '',
            source TEXT NOT NULL,
            client_ip TEXT,
            user_agent TEXT,
            request_id TEXT,
            connection_id TEXT,
            connection_name TEXT,
            database TEXT,
            schema_name TEXT,
            operation TEXT NOT NULL,
            sql_text TEXT,
            sql_digest TEXT,
            risk_level TEXT,
            decision TEXT NOT NULL,
            rule_id TEXT,
            policy_version INTEGER,
            approval_id TEXT,
            outcome TEXT NOT NULL,
            error_code TEXT,
            error_message TEXT,
            affected_rows INTEGER,
            duration_ms INTEGER,
            details_json TEXT,
            prev_hash TEXT NOT NULL,
            event_hash TEXT NOT NULL,
            hash_scheme TEXT NOT NULL DEFAULT 'sha256-v1',
            event_type TEXT NOT NULL DEFAULT 'domain',
            resource_type TEXT,
            resource_id TEXT,
            table_name TEXT,
            statement_index INTEGER,
            execution_id TEXT,
            request_method TEXT,
            request_path TEXT,
            http_status INTEGER,
            redaction_mode TEXT,
            sql_fingerprint TEXT,
            matched_rule_ids_json TEXT NOT NULL DEFAULT '[]',
            policy_bundle_hash TEXT,
            actor_verified INTEGER NOT NULL DEFAULT 0,
            on_behalf_of TEXT,
            delegated_by TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_audit_events_seq_time ON audit_events(seq DESC);
        CREATE INDEX IF NOT EXISTS idx_audit_events_time ON audit_events(occurred_at_ms DESC, seq DESC);
        CREATE INDEX IF NOT EXISTS idx_audit_events_actor ON audit_events(actor_id, occurred_at_ms DESC);
        CREATE INDEX IF NOT EXISTS idx_audit_events_connection ON audit_events(connection_id, occurred_at_ms DESC);
        CREATE INDEX IF NOT EXISTS idx_audit_events_operation ON audit_events(operation, occurred_at_ms DESC);
        CREATE INDEX IF NOT EXISTS idx_audit_events_decision ON audit_events(decision, occurred_at_ms DESC);
        CREATE INDEX IF NOT EXISTS idx_audit_events_request ON audit_events(request_id);
        CREATE TABLE IF NOT EXISTS audit_chain_head (
            chain_id TEXT PRIMARY KEY,
            last_seq INTEGER NOT NULL,
            last_hash TEXT NOT NULL,
            event_count INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit_outbox (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sink_name TEXT NOT NULL,
            event_seq INTEGER NOT NULL,
            event_id TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            state TEXT NOT NULL DEFAULT 'pending',
            attempts INTEGER NOT NULL DEFAULT 0,
            next_attempt_at_ms INTEGER NOT NULL DEFAULT 0,
            last_error TEXT,
            created_at_ms INTEGER NOT NULL,
            delivered_at_ms INTEGER,
            UNIQUE(sink_name, event_seq)
        );
        CREATE INDEX IF NOT EXISTS idx_audit_outbox_pending ON audit_outbox(state, next_attempt_at_ms);
        CREATE TABLE IF NOT EXISTS audit_chain_floor (
            chain_id TEXT PRIMARY KEY,
            seq INTEGER NOT NULL,
            hash TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit_export_state (
            sink_name TEXT PRIMARY KEY,
            last_exported_seq INTEGER NOT NULL DEFAULT 0,
            updated_at_ms INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit_checkpoints (
            seq INTEGER PRIMARY KEY,
            event_hash TEXT NOT NULL,
            signed_at TEXT NOT NULL,
            signature TEXT,
            exported_at TEXT
        );
        CREATE TRIGGER IF NOT EXISTS audit_checkpoints_no_update
            BEFORE UPDATE ON audit_checkpoints
            BEGIN SELECT RAISE(ABORT, 'AUDIT_CHECKPOINT_IMMUTABLE'); END;
        CREATE TRIGGER IF NOT EXISTS audit_checkpoints_no_delete
            BEFORE DELETE ON audit_checkpoints
            BEGIN SELECT RAISE(ABORT, 'AUDIT_CHECKPOINT_IMMUTABLE'); END;
        CREATE TRIGGER IF NOT EXISTS audit_events_no_update
            BEFORE UPDATE ON audit_events
            BEGIN SELECT RAISE(ABORT, 'AUDIT_APPEND_ONLY'); END;
        CREATE TRIGGER IF NOT EXISTS audit_events_no_delete
            BEFORE DELETE ON audit_events
            BEGIN SELECT RAISE(ABORT, 'AUDIT_APPEND_ONLY'); END;
        CREATE TRIGGER IF NOT EXISTS audit_chain_head_no_delete
            BEFORE DELETE ON audit_chain_head
            BEGIN SELECT RAISE(ABORT, 'AUDIT_CHAIN_HEAD_IMMUTABLE'); END;
        CREATE TRIGGER IF NOT EXISTS audit_chain_head_monotonic
            BEFORE UPDATE ON audit_chain_head
            WHEN NEW.last_seq != OLD.last_seq + 1
            BEGIN SELECT RAISE(ABORT, 'AUDIT_CHAIN_HEAD_ROLLBACK'); END;",
    )
    .map_err(|error| format!("AUDIT_SCHEMA: {error}"))?;

    // Existing databases predate the extended columns; add them before any
    // index or query references them.
    super::ensure_table_columns(conn, "audit_events", EXTENDED_COLUMNS)
        .map_err(|error| format!("AUDIT_SCHEMA_MIGRATE: {error}"))?;
    conn.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_audit_events_execution
             ON audit_events(execution_id, statement_index);
         CREATE INDEX IF NOT EXISTS idx_audit_events_rule ON audit_events(rule_id);",
    )
    .map_err(|error| format!("AUDIT_SCHEMA_INDEX: {error}"))?;

    // Never recreate a missing head while events exist: that would silently
    // reset the chain to genesis and make tail/head deletion look healthy.
    let head_exists: bool = conn
        .query_row("SELECT EXISTS(SELECT 1 FROM audit_chain_head WHERE chain_id = ?1)", [CHAIN_ID], |row| row.get(0))
        .map_err(|error| format!("AUDIT_HEAD_QUERY: {error}"))?;
    if !head_exists {
        let events_exist: bool = conn
            .query_row("SELECT EXISTS(SELECT 1 FROM audit_events)", [], |row| row.get(0))
            .map_err(|error| format!("AUDIT_EVENTS_QUERY: {error}"))?;
        if events_exist {
            return Err("AUDIT_CHAIN_HEAD_MISSING".to_string());
        }
        let genesis = genesis_hash(CHAIN_ID);
        conn.execute(
            "INSERT OR IGNORE INTO audit_chain_head (chain_id, last_seq, last_hash, event_count, updated_at) \
             VALUES (?1, 0, ?2, 0, ?3)",
            params![CHAIN_ID, genesis, now_rfc3339()],
        )
        .map_err(|error| format!("AUDIT_HEAD_SEED: {error}"))?;
    }
    Ok(())
}

impl Storage {
    pub async fn insert_audit_event(&self, event: AuditEventInsert) -> Result<AuditEvent, String> {
        self.with_audit_conn(move |conn| {
            let tx =
                conn.transaction_with_behavior(TransactionBehavior::Immediate).map_err(|error| error.to_string())?;
            let inserted = insert_in_tx(&tx, &event)?;
            tx.commit().map_err(|error| error.to_string())?;
            Ok(inserted)
        })
        .await
    }

    pub async fn insert_audit_events_batch(&self, events: Vec<AuditEventInsert>) -> Result<Vec<AuditEvent>, String> {
        self.with_audit_conn(move |conn| {
            let tx =
                conn.transaction_with_behavior(TransactionBehavior::Immediate).map_err(|error| error.to_string())?;
            let mut inserted = Vec::with_capacity(events.len());
            for event in &events {
                inserted.push(insert_in_tx(&tx, event)?);
            }
            tx.commit().map_err(|error| error.to_string())?;
            Ok(inserted)
        })
        .await
    }

    pub async fn query_audit_events(&self, query: AuditQuery) -> Result<AuditPage, String> {
        self.with_audit_conn(move |conn| {
            let limit = query.limit.unwrap_or(DEFAULT_QUERY_LIMIT).clamp(1, MAX_QUERY_LIMIT);
            let mut sql = format!("SELECT {EVENT_COLUMNS} FROM audit_events WHERE 1=1");
            let mut values: Vec<Value> = Vec::new();
            if let Some(actor_id) = query.actor_id {
                sql.push_str(" AND actor_id = ?");
                values.push(Value::Text(actor_id));
            }
            if let Some(connection_id) = query.connection_id {
                sql.push_str(" AND connection_id = ?");
                values.push(Value::Text(connection_id));
            }
            if let Some(database) = query.database {
                sql.push_str(" AND database = ?");
                values.push(Value::Text(database));
            }
            if let Some(operation) = query.operation {
                sql.push_str(" AND operation = ?");
                values.push(Value::Text(operation.as_str().to_string()));
            }
            if let Some(decision) = query.decision {
                sql.push_str(" AND decision = ?");
                values.push(Value::Text(decision.as_str().to_string()));
            }
            if let Some(outcome) = query.outcome {
                sql.push_str(" AND outcome = ?");
                values.push(Value::Text(outcome.as_str().to_string()));
            }
            if let Some(sql_contains) = query.sql_contains {
                sql.push_str(" AND sql_text LIKE ? ESCAPE '\\'");
                values.push(Value::Text(format!("%{}%", like_escape(&sql_contains))));
            }
            if let Some(from_ms) = query.from_ms {
                sql.push_str(" AND occurred_at_ms >= ?");
                values.push(Value::Integer(from_ms));
            }
            if let Some(to_ms) = query.to_ms {
                sql.push_str(" AND occurred_at_ms <= ?");
                values.push(Value::Integer(to_ms));
            }
            if let Some(cursor_seq) = query.cursor_seq {
                sql.push_str(" AND seq < ?");
                values.push(Value::Integer(cursor_seq));
            }
            sql.push_str(" ORDER BY seq DESC LIMIT ?");
            values.push(Value::Integer(i64::try_from(limit).unwrap_or(i64::MAX)));

            let mut stmt = conn.prepare(&sql).map_err(|error| error.to_string())?;
            let rows =
                stmt.query_map(params_from_iter(values.iter()), row_to_event).map_err(|error| error.to_string())?;
            let events = rows.collect::<Result<Vec<_>, _>>().map_err(|error| error.to_string())?;
            let next_cursor = if events.len() == limit { events.last().map(|event| event.seq) } else { None };
            Ok(AuditPage { events, next_cursor })
        })
        .await
    }

    pub async fn audit_event_by_id(&self, event_id: String) -> Result<Option<AuditEvent>, String> {
        self.with_audit_conn(move |conn| {
            conn.query_row(
                &format!("SELECT {EVENT_COLUMNS} FROM audit_events WHERE event_id = ?1"),
                [event_id],
                row_to_event,
            )
            .optional()
            .map_err(|error| error.to_string())
        })
        .await
    }

    /// Events after `after_seq`, oldest first, for the export worker.
    pub async fn audit_events_after(&self, after_seq: i64, limit: usize) -> Result<Vec<AuditEvent>, String> {
        let limit = limit.clamp(1, 1000) as i64;
        self.with_audit_conn(move |conn| {
            let mut stmt = conn
                .prepare(&format!("SELECT {EVENT_COLUMNS} FROM audit_events WHERE seq > ?1 ORDER BY seq ASC LIMIT ?2"))
                .map_err(|error| error.to_string())?;
            let rows = stmt.query_map(params![after_seq, limit], row_to_event).map_err(|error| error.to_string())?;
            rows.collect::<Result<Vec<_>, _>>().map_err(|error| error.to_string())
        })
        .await
    }

    pub async fn audit_export_state(&self, sink_name: String) -> Result<Option<i64>, String> {
        self.with_audit_conn(move |conn| {
            conn.query_row(
                "SELECT last_exported_seq FROM audit_export_state WHERE sink_name = ?1",
                [sink_name],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(|error| error.to_string())
        })
        .await
    }

    pub async fn set_audit_export_state(&self, sink_name: String, last_seq: i64) -> Result<(), String> {
        self.with_audit_conn(move |conn| {
            conn.execute(
                "INSERT INTO audit_export_state (sink_name, last_exported_seq, updated_at_ms) \
                 VALUES (?1, ?2, ?3) \
                 ON CONFLICT(sink_name) DO UPDATE SET last_exported_seq = excluded.last_exported_seq, \
                 updated_at_ms = excluded.updated_at_ms",
                params![sink_name, last_seq, Utc::now().timestamp_millis()],
            )
            .map_err(|error| error.to_string())?;
            Ok(())
        })
        .await
    }

    /// Aggregates over an optional time window. The audit UI shows these so an
    /// operator can see spikes without exporting the whole log.
    pub async fn audit_stats(&self, from_ms: Option<i64>, to_ms: Option<i64>) -> Result<AuditStats, String> {
        self.with_audit_conn(move |conn| {
            let mut where_sql = String::from(" WHERE 1=1");
            let mut values: Vec<Value> = Vec::new();
            if let Some(from_ms) = from_ms {
                where_sql.push_str(" AND occurred_at_ms >= ?");
                values.push(Value::Integer(from_ms));
            }
            if let Some(to_ms) = to_ms {
                where_sql.push_str(" AND occurred_at_ms <= ?");
                values.push(Value::Integer(to_ms));
            }
            let total = conn
                .query_row(
                    &format!("SELECT COUNT(*) FROM audit_events{where_sql}"),
                    params_from_iter(values.iter()),
                    |row| row.get::<_, i64>(0),
                )
                .map_err(|error| error.to_string())?;
            let bucket = |column: &str| -> Result<Vec<AuditCount>, String> {
                let mut stmt = conn
                    .prepare(&format!(
                        "SELECT COALESCE({column}, ''), COUNT(*) FROM audit_events{where_sql} \
                         GROUP BY 1 ORDER BY 2 DESC"
                    ))
                    .map_err(|error| error.to_string())?;
                let rows = stmt
                    .query_map(params_from_iter(values.iter()), |row| {
                        Ok(AuditCount { key: row.get(0)?, count: row.get(1)? })
                    })
                    .map_err(|error| error.to_string())?;
                rows.collect::<Result<Vec<_>, _>>().map_err(|error| error.to_string())
            };
            Ok(AuditStats {
                total,
                by_decision: bucket("decision")?,
                by_operation: bucket("operation")?,
                by_actor: bucket("actor_id")?,
                by_risk: bucket("risk_level")?,
            })
        })
        .await
    }

    pub async fn audit_chain_head(&self) -> Result<AuditChainHead, String> {
        self.with_audit_conn(|conn| read_head_sync(conn)).await.map(|(last_seq, last_hash, event_count)| {
            AuditChainHead { chain_id: CHAIN_ID.to_string(), last_seq, last_hash, event_count }
        })
    }

    /// Anchors the current head. The signature uses `DBX_AUDIT_CHECKPOINT_KEY`,
    /// which must be kept outside the database: a key stored next to the data
    /// proves nothing after an attacker can edit both.
    pub async fn create_audit_checkpoint(&self) -> Result<AuditCheckpoint, String> {
        let key = std::env::var("DBX_AUDIT_CHECKPOINT_KEY")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        self.with_audit_conn(move |conn| {
            let (last_seq, last_hash, _) = read_head_sync(conn)?;
            if last_seq == 0 {
                return Err("AUDIT_CHAIN_EMPTY".to_string());
            }
            let signature = key.map(|key| {
                crate::audit::signature::hmac_sha256_hex(
                    key.as_bytes(),
                    crate::audit::signature::checkpoint_payload(CHAIN_ID, last_seq, &last_hash).as_bytes(),
                )
            });
            let signed_at = now_rfc3339();
            conn.execute(
                "INSERT OR IGNORE INTO audit_checkpoints (seq, event_hash, signed_at, signature) \
                 VALUES (?1, ?2, ?3, ?4)",
                params![last_seq, last_hash, signed_at, signature],
            )
            .map_err(|error| format!("AUDIT_CHECKPOINT: {error}"))?;
            read_checkpoint_sync(conn, last_seq)?.ok_or_else(|| "AUDIT_CHECKPOINT_MISSING".to_string())
        })
        .await
    }

    /// Deletes a retained prefix of the chain.
    ///
    /// The prefix may only be removed when a checkpoint and an external export
    /// both cover it, so a local deletion can never be the only copy. The last
    /// deleted hash becomes the chain floor that verification anchors on.
    pub async fn prune_audit_events(&self, up_to_seq: i64, actor: String, reason: String) -> Result<i64, String> {
        self.with_audit_conn(move |conn| {
            let (head_seq, _, _) = read_head_sync(conn)?;
            if up_to_seq <= 0 || up_to_seq >= head_seq {
                return Err("AUDIT_PRUNE_RANGE_INVALID".to_string());
            }
            let checkpoint_seq: Option<i64> = conn
                .query_row("SELECT MAX(seq) FROM audit_checkpoints", [], |row| row.get(0))
                .map_err(|error| error.to_string())?;
            if checkpoint_seq.unwrap_or(0) < up_to_seq {
                return Err("AUDIT_PRUNE_CHECKPOINT_REQUIRED".to_string());
            }
            let exported: i64 = conn
                .query_row("SELECT COALESCE(MAX(last_exported_seq), 0) FROM audit_export_state", [], |row| row.get(0))
                .map_err(|error| error.to_string())?;
            if exported < up_to_seq {
                return Err("AUDIT_PRUNE_EXPORT_REQUIRED".to_string());
            }
            if read_floor_sync(conn)?.map(|(seq, _)| seq).unwrap_or(0) >= up_to_seq {
                return Err("AUDIT_PRUNE_ALREADY_PRUNED".to_string());
            }
            let hash: String = conn
                .query_row("SELECT event_hash FROM audit_events WHERE seq = ?1", [up_to_seq], |row| row.get(0))
                .optional()
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "AUDIT_PRUNE_ANCHOR_MISSING".to_string())?;

            let tx =
                conn.transaction_with_behavior(TransactionBehavior::Immediate).map_err(|error| error.to_string())?;
            tx.execute_batch("DROP TRIGGER IF EXISTS audit_events_no_delete;").map_err(|error| error.to_string())?;
            let deleted = tx
                .execute("DELETE FROM audit_events WHERE seq <= ?1", [up_to_seq])
                .map_err(|error| error.to_string())?;
            tx.execute_batch(
                "CREATE TRIGGER IF NOT EXISTS audit_events_no_delete
                    BEFORE DELETE ON audit_events
                    BEGIN SELECT RAISE(ABORT, 'AUDIT_APPEND_ONLY'); END;",
            )
            .map_err(|error| error.to_string())?;
            tx.execute(
                "INSERT INTO audit_chain_floor (chain_id, seq, hash, updated_at) VALUES (?1, ?2, ?3, ?4) \
                 ON CONFLICT(chain_id) DO UPDATE SET seq = excluded.seq, hash = excluded.hash, \
                 updated_at = excluded.updated_at",
                params![CHAIN_ID, up_to_seq, hash, now_rfc3339()],
            )
            .map_err(|error| error.to_string())?;
            tx.commit().map_err(|error| error.to_string())?;
            let _ = (actor, reason);
            Ok(i64::try_from(deleted).unwrap_or(i64::MAX))
        })
        .await
    }

    /// Oldest retained event, for retention reporting only. Automatic
    /// deletion is not enabled: a segment may only be removed after a copy is
    /// anchored outside the database.
    pub async fn audit_oldest_event_ms(&self) -> Result<Option<i64>, String> {
        self.with_audit_conn(|conn| {
            conn.query_row("SELECT MIN(occurred_at_ms) FROM audit_events", [], |row| row.get::<_, Option<i64>>(0))
                .map_err(|error| error.to_string())
        })
        .await
    }

    pub async fn audit_checkpoints(&self, limit: usize) -> Result<Vec<AuditCheckpoint>, String> {
        let limit = limit.clamp(1, 1000) as i64;
        self.with_audit_conn(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT seq, event_hash, signed_at, signature, exported_at FROM audit_checkpoints \
                     ORDER BY seq DESC LIMIT ?1",
                )
                .map_err(|error| error.to_string())?;
            let rows = stmt.query_map([limit], row_to_checkpoint).map_err(|error| error.to_string())?;
            rows.collect::<Result<Vec<_>, _>>().map_err(|error| error.to_string())
        })
        .await
    }

    /// Verifies the tail starting from the newest checkpoint.
    ///
    /// A missing checkpoint means "verify from genesis" — the caller still gets
    /// a full report, just without the off-host anchor.
    pub async fn verify_audit_chain_from_checkpoint(&self) -> Result<AuditCheckpointReport, String> {
        self.with_audit_conn(|conn| {
            let checkpoint = conn
                .query_row(
                    "SELECT seq, event_hash, signed_at, signature, exported_at FROM audit_checkpoints \
                     ORDER BY seq DESC LIMIT 1",
                    [],
                    row_to_checkpoint,
                )
                .optional()
                .map_err(|error| error.to_string())?;
            let Some(checkpoint) = checkpoint else {
                return Ok(AuditCheckpointReport { checkpoint: None, report: verify_chain_sync(conn, None, None)? });
            };
            let stored_hash: Option<String> = conn
                .query_row("SELECT event_hash FROM audit_events WHERE seq = ?1", [checkpoint.seq], |row| row.get(0))
                .optional()
                .map_err(|error| error.to_string())?;
            if stored_hash.as_deref() != Some(checkpoint.event_hash.as_str()) {
                return Ok(AuditCheckpointReport {
                    report: AuditChainReport {
                        checked: 0,
                        first_broken_seq: Some(checkpoint.seq),
                        head_seq: checkpoint.seq,
                        head_hash: checkpoint.event_hash.clone(),
                    },
                    checkpoint: Some(checkpoint),
                });
            }
            let report = verify_chain_sync(conn, Some(checkpoint.seq.saturating_add(1)), None)?;
            Ok(AuditCheckpointReport { checkpoint: Some(checkpoint), report })
        })
        .await
    }

    pub async fn verify_audit_chain(
        &self,
        from_seq: Option<i64>,
        to_seq: Option<i64>,
    ) -> Result<AuditChainReport, String> {
        self.with_audit_conn(move |conn| verify_chain_sync(conn, from_seq, to_seq)).await
    }

    /// Only used by migration tests that need to write a legacy-scheme row.
    #[cfg(all(test, feature = "enterprise-audit"))]
    pub async fn insert_audit_event_with_scheme(
        &self,
        event: AuditEventInsert,
        hash_scheme: &str,
    ) -> Result<AuditEvent, String> {
        let scheme = hash_scheme.to_string();
        self.with_audit_conn(move |conn| {
            let tx =
                conn.transaction_with_behavior(TransactionBehavior::Immediate).map_err(|error| error.to_string())?;
            let inserted = insert_in_tx_with_scheme(&tx, &event, &scheme)?;
            tx.commit().map_err(|error| error.to_string())?;
            Ok(inserted)
        })
        .await
    }
}

fn insert_in_tx(tx: &rusqlite::Transaction<'_>, event: &AuditEventInsert) -> Result<AuditEvent, String> {
    insert_in_tx_with_scheme(tx, event, CURRENT_HASH_SCHEME)
}

fn insert_in_tx_with_scheme(
    tx: &rusqlite::Transaction<'_>,
    event: &AuditEventInsert,
    hash_scheme: &str,
) -> Result<AuditEvent, String> {
    let (last_seq, last_hash, _) = read_head_sync(tx)?;
    let seq = last_seq.checked_add(1).ok_or_else(|| "AUDIT_SEQ_OVERFLOW".to_string())?;
    let occurred_at_ms = chrono::DateTime::parse_from_rfc3339(&event.occurred_at)
        .map(|value| value.timestamp_millis())
        .unwrap_or_else(|_| Utc::now().timestamp_millis());
    let event_hash = compute_event_hash(event, seq, &last_hash, occurred_at_ms, hash_scheme)?;
    let roles_json = serde_json::to_string(&event.actor.roles).map_err(|error| error.to_string())?;
    let matched_rule_ids_json = serde_json::to_string(&event.matched_rule_ids).map_err(|error| error.to_string())?;

    tx.execute(
        "INSERT INTO audit_events (
            seq, event_id, occurred_at, occurred_at_ms, actor_id, actor_display_name, actor_kind,
            actor_roles_json, tenant_id, session_id, auth_method, source, client_ip, user_agent,
            request_id, connection_id, connection_name, database, schema_name, operation, sql_text,
            sql_digest, risk_level, decision, rule_id, policy_version, approval_id, outcome, error_code,
            error_message, affected_rows, duration_ms, details_json, prev_hash, event_hash, hash_scheme,
            event_type, resource_type, resource_id, table_name, statement_index, execution_id,
            request_method, request_path, http_status, redaction_mode, sql_fingerprint,
            matched_rule_ids_json, policy_bundle_hash, actor_verified, on_behalf_of, delegated_by
         ) VALUES (
            :seq, :event_id, :occurred_at, :occurred_at_ms, :actor_id, :actor_display_name, :actor_kind,
            :actor_roles_json, :tenant_id, :session_id, :auth_method, :source, :client_ip, :user_agent,
            :request_id, :connection_id, :connection_name, :database, :schema_name, :operation, :sql_text,
            :sql_digest, :risk_level, :decision, :rule_id, :policy_version, :approval_id, :outcome,
            :error_code, :error_message, :affected_rows, :duration_ms, :details_json, :prev_hash,
            :event_hash, :hash_scheme, :event_type, :resource_type, :resource_id, :table_name,
            :statement_index, :execution_id, :request_method, :request_path, :http_status,
            :redaction_mode, :sql_fingerprint, :matched_rule_ids_json, :policy_bundle_hash,
            :actor_verified, :on_behalf_of, :delegated_by
         )",
        rusqlite::named_params! {
            ":seq": seq,
            ":event_id": event.event_id,
            ":occurred_at": event.occurred_at,
            ":occurred_at_ms": occurred_at_ms,
            ":actor_id": event.actor.id,
            ":actor_display_name": event.actor.display_name,
            ":actor_kind": event.actor.kind.as_str(),
            ":actor_roles_json": roles_json,
            ":tenant_id": event.actor.tenant_id,
            ":session_id": event.actor.session_id,
            ":auth_method": event.actor.auth_method,
            ":source": event.source.as_str(),
            ":client_ip": event.client_ip,
            ":user_agent": event.user_agent,
            ":request_id": event.request_id,
            ":connection_id": event.connection_id,
            ":connection_name": event.connection_name,
            ":database": event.database,
            ":schema_name": event.schema_name,
            ":operation": event.operation.as_str(),
            ":sql_text": event.sql_text,
            ":sql_digest": event.sql_digest,
            ":risk_level": event.risk_level,
            ":decision": event.decision.as_str(),
            ":rule_id": event.rule_id,
            ":policy_version": event.policy_version,
            ":approval_id": event.approval_id,
            ":outcome": event.outcome.as_str(),
            ":error_code": event.error_code,
            ":error_message": event.error_message,
            ":affected_rows": event.affected_rows,
            ":duration_ms": event.duration_ms,
            ":details_json": event.details_json,
            ":prev_hash": last_hash,
            ":event_hash": event_hash,
            ":hash_scheme": hash_scheme,
            ":event_type": event.event_type,
            ":resource_type": event.resource_type,
            ":resource_id": event.resource_id,
            ":table_name": event.table_name,
            ":statement_index": event.statement_index,
            ":execution_id": event.execution_id,
            ":request_method": event.request_method,
            ":request_path": event.request_path,
            ":http_status": event.http_status,
            ":redaction_mode": event.redaction_mode,
            ":sql_fingerprint": event.sql_fingerprint,
            ":matched_rule_ids_json": matched_rule_ids_json,
            ":policy_bundle_hash": event.policy_bundle_hash,
            ":actor_verified": event.actor_verified,
            ":on_behalf_of": event.on_behalf_of,
            ":delegated_by": event.delegated_by,
        },
    )
    .map_err(|error| format!("AUDIT_INSERT: {error}"))?;

    let updated = tx
        .execute(
            "UPDATE audit_chain_head
             SET last_seq = ?1, last_hash = ?2, event_count = event_count + 1, updated_at = ?3
             WHERE chain_id = ?4 AND last_seq = ?5",
            params![seq, event_hash, now_rfc3339(), CHAIN_ID, last_seq],
        )
        .map_err(|error| error.to_string())?;
    if updated != 1 {
        return Err("AUDIT_CHAIN_CAS_CONFLICT".to_string());
    }

    Ok(AuditEvent { seq, event: event.clone(), prev_hash: last_hash, event_hash })
}

fn read_checkpoint_sync(conn: &rusqlite::Connection, seq: i64) -> Result<Option<AuditCheckpoint>, String> {
    conn.query_row(
        "SELECT seq, event_hash, signed_at, signature, exported_at FROM audit_checkpoints WHERE seq = ?1",
        [seq],
        row_to_checkpoint,
    )
    .optional()
    .map_err(|error| error.to_string())
}

fn row_to_checkpoint(row: &rusqlite::Row<'_>) -> rusqlite::Result<AuditCheckpoint> {
    Ok(AuditCheckpoint {
        seq: row.get(0)?,
        event_hash: row.get(1)?,
        signed_at: row.get(2)?,
        signature: row.get(3)?,
        exported_at: row.get(4)?,
    })
}

fn read_floor_sync(conn: &rusqlite::Connection) -> Result<Option<(i64, String)>, String> {
    conn.query_row("SELECT seq, hash FROM audit_chain_floor WHERE chain_id = ?1", [CHAIN_ID], |row| {
        Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
    })
    .optional()
    .map_err(|error| error.to_string())
}

fn read_head_sync(conn: &rusqlite::Connection) -> Result<(i64, String, i64), String> {
    conn.query_row(
        "SELECT last_seq, last_hash, event_count FROM audit_chain_head WHERE chain_id = ?1",
        [CHAIN_ID],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )
    .optional()
    .map_err(|error| error.to_string())?
    .ok_or_else(|| "AUDIT_CHAIN_HEAD_MISSING".to_string())
}

fn verify_chain_sync(
    conn: &rusqlite::Connection,
    from_seq: Option<i64>,
    to_seq: Option<i64>,
) -> Result<AuditChainReport, String> {
    let head = read_head_sync(conn)?;
    let max_seq: Option<i64> =
        conn.query_row("SELECT MAX(seq) FROM audit_events", [], |row| row.get(0)).map_err(|error| error.to_string())?;
    // A lowered/rolled-back head must not hide rows that still exist above it.
    if max_seq.unwrap_or(0) > head.0 {
        return Ok(AuditChainReport {
            checked: 0,
            first_broken_seq: Some(head.0.saturating_add(1)),
            head_seq: head.0,
            head_hash: head.1,
        });
    }

    // A pruned deployment verifies from its retained floor; rows below it were
    // deleted only after a checkpoint and an external copy covered them.
    let floor = read_floor_sync(conn)?;
    let floor_seq = floor.as_ref().map(|(seq, _)| *seq).unwrap_or(0);
    let from = from_seq.unwrap_or(floor_seq.saturating_add(1)).max(floor_seq.saturating_add(1)).max(1);
    let to = to_seq.unwrap_or(head.0).min(head.0);
    if from > to {
        return Ok(AuditChainReport { checked: 0, first_broken_seq: None, head_seq: head.0, head_hash: head.1 });
    }

    let anchor = if let Some((_, floor_hash)) = floor.as_ref().filter(|(seq, _)| from == seq.saturating_add(1)) {
        Some(floor_hash.clone())
    } else if from == 1 && floor_seq == 0 {
        Some(genesis_hash(CHAIN_ID))
    } else {
        conn.query_row("SELECT event_hash FROM audit_events WHERE seq = ?1", [from - 1], |row| row.get::<_, String>(0))
            .optional()
            .map_err(|error| error.to_string())?
    };
    let Some(mut expected_prev) = anchor else {
        // A missing anchor is itself a break; do not turn it into a 500 that
        // hides the chain state from the verifier.
        return Ok(AuditChainReport {
            checked: 0,
            first_broken_seq: Some(from.saturating_sub(1).max(1)),
            head_seq: head.0,
            head_hash: head.1,
        });
    };

    let mut stmt = conn
        .prepare(&format!(
            "SELECT {EVENT_COLUMNS}, occurred_at_ms, hash_scheme FROM audit_events \
             WHERE seq >= ?1 AND seq <= ?2 ORDER BY seq ASC"
        ))
        .map_err(|error| error.to_string())?;
    let mut rows = stmt.query(params![from, to]).map_err(|error| error.to_string())?;
    let mut checked = 0_i64;
    let mut first_broken_seq = None;
    let mut expected_seq = from;
    while let Some(row) = rows.next().map_err(|error| error.to_string())? {
        let stored = row_to_stored_event(row).map_err(|error| error.to_string())?;
        let event = stored.event;
        if event.seq != expected_seq {
            first_broken_seq = Some(expected_seq);
            break;
        }
        // Dispatch on the scheme stored with the row, not on the current
        // constant: rows written by an older binary must keep verifying.
        let recomputed = match compute_event_hash(
            &event.event,
            event.seq,
            &expected_prev,
            stored.occurred_at_ms,
            &stored.hash_scheme,
        ) {
            Ok(hash) => hash,
            Err(_) => {
                first_broken_seq = Some(event.seq);
                break;
            }
        };
        if event.prev_hash != expected_prev || event.event_hash != recomputed {
            first_broken_seq = Some(event.seq);
            break;
        }
        expected_prev = event.event_hash;
        checked += 1;
        expected_seq = expected_seq.saturating_add(1);
    }

    if first_broken_seq.is_none() && to == head.0 {
        let expected_count = to.saturating_sub(from).saturating_add(1);
        if checked != expected_count {
            first_broken_seq = Some(expected_seq);
        } else if expected_prev != head.1 {
            first_broken_seq = Some(to);
        }
    }

    Ok(AuditChainReport { checked, first_broken_seq, head_seq: head.0, head_hash: head.1 })
}

fn row_to_event(row: &rusqlite::Row<'_>) -> rusqlite::Result<AuditEvent> {
    // Read by name: the column list has grown repeatedly and positional
    // indices silently shift when a column is inserted.
    let roles_json: String = row.get("actor_roles_json")?;
    let matched_rule_ids_json: String = row.get("matched_rule_ids_json")?;
    let actor = Actor {
        id: row.get("actor_id")?,
        display_name: row.get("actor_display_name")?,
        kind: parse_actor_kind(row.get::<_, String>("actor_kind")?),
        roles: serde_json::from_str(&roles_json).unwrap_or_default(),
        tenant_id: row.get("tenant_id")?,
        session_id: row.get("session_id")?,
        auth_method: row.get("auth_method")?,
    };
    let event = AuditEventInsert {
        event_id: row.get("event_id")?,
        occurred_at: row.get("occurred_at")?,
        event_type: row.get("event_type")?,
        actor,
        source: parse_source(row.get::<_, String>("source")?),
        client_ip: row.get("client_ip")?,
        user_agent: row.get("user_agent")?,
        request_id: row.get("request_id")?,
        request_method: row.get("request_method")?,
        request_path: row.get("request_path")?,
        http_status: row.get("http_status")?,
        connection_id: row.get("connection_id")?,
        connection_name: row.get("connection_name")?,
        database: row.get("database")?,
        schema_name: row.get("schema_name")?,
        table_name: row.get("table_name")?,
        resource_type: row.get("resource_type")?,
        resource_id: row.get("resource_id")?,
        operation: parse_operation(row.get::<_, String>("operation")?),
        sql_text: row.get("sql_text")?,
        sql_digest: row.get("sql_digest")?,
        sql_fingerprint: row.get("sql_fingerprint")?,
        risk_level: row.get("risk_level")?,
        decision: parse_decision(row.get::<_, String>("decision")?),
        rule_id: row.get("rule_id")?,
        matched_rule_ids: serde_json::from_str(&matched_rule_ids_json).unwrap_or_default(),
        policy_version: row.get("policy_version")?,
        policy_bundle_hash: row.get("policy_bundle_hash")?,
        approval_id: row.get("approval_id")?,
        outcome: parse_outcome(row.get::<_, String>("outcome")?),
        error_code: row.get("error_code")?,
        error_message: row.get("error_message")?,
        affected_rows: row.get("affected_rows")?,
        duration_ms: row.get("duration_ms")?,
        details_json: row.get("details_json")?,
        execution_id: row.get("execution_id")?,
        statement_index: row.get("statement_index")?,
        redaction_mode: row.get("redaction_mode")?,
        actor_verified: row.get::<_, i64>("actor_verified")? != 0,
        on_behalf_of: row.get("on_behalf_of")?,
        delegated_by: row.get("delegated_by")?,
    };
    Ok(AuditEvent { seq: row.get("seq")?, event, prev_hash: row.get("prev_hash")?, event_hash: row.get("event_hash")? })
}

/// A row plus the two fields that are stored but not exposed on [`AuditEvent`].
/// Verification needs them to recompute the hash under the row's own scheme.
struct StoredEvent {
    event: AuditEvent,
    occurred_at_ms: i64,
    hash_scheme: String,
}

/// Expects the row to include `occurred_at_ms` and `hash_scheme`.
fn row_to_stored_event(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredEvent> {
    Ok(StoredEvent {
        event: row_to_event(row)?,
        occurred_at_ms: row.get("occurred_at_ms")?,
        hash_scheme: row.get("hash_scheme")?,
    })
}

fn parse_actor_kind(value: String) -> ActorKind {
    match value.as_str() {
        "bootstrap" => ActorKind::Bootstrap,
        "human" => ActorKind::Human,
        "service" => ActorKind::Service,
        "ai_agent" => ActorKind::AiAgent,
        _ => ActorKind::System,
    }
}

fn parse_source(value: String) -> AuditSource {
    match value.as_str() {
        "web" => AuditSource::Web,
        "desktop" => AuditSource::Desktop,
        "cli" => AuditSource::Cli,
        "mcp" => AuditSource::Mcp,
        "ai" => AuditSource::Ai,
        _ => AuditSource::System,
    }
}

fn parse_operation(value: String) -> AuditOperation {
    match value.as_str() {
        "query" => AuditOperation::Query,
        "dml" => AuditOperation::Dml,
        "ddl" => AuditOperation::Ddl,
        "transaction" => AuditOperation::Transaction,
        "export" => AuditOperation::Export,
        "import" => AuditOperation::Import,
        "backup" => AuditOperation::Backup,
        "config" => AuditOperation::Config,
        "connection" => AuditOperation::Connection,
        "auth" => AuditOperation::Auth,
        "policy" => AuditOperation::Policy,
        "approval" => AuditOperation::Approval,
        _ => AuditOperation::Admin,
    }
}

fn parse_decision(value: String) -> AuditDecision {
    match value.as_str() {
        "allowed" => AuditDecision::Allowed,
        "denied" => AuditDecision::Denied,
        "warned" => AuditDecision::Warned,
        "approval_required" => AuditDecision::ApprovalRequired,
        "blocked" => AuditDecision::Blocked,
        _ => AuditDecision::Error,
    }
}

fn parse_outcome(value: String) -> AuditOutcome {
    match value.as_str() {
        "success" => AuditOutcome::Success,
        "error" => AuditOutcome::Error,
        "canceled" => AuditOutcome::Canceled,
        "not_started" => AuditOutcome::NotStarted,
        _ => AuditOutcome::Unknown,
    }
}

#[derive(serde::Serialize)]
struct CanonicalEvent<'a> {
    version: &'a str,
    chain_id: &'a str,
    seq: i64,
    prev_hash: &'a str,
    event_id: &'a str,
    occurred_at: &'a str,
    actor_id: &'a str,
    actor_display_name: &'a str,
    actor_kind: &'a str,
    actor_roles: &'a [String],
    tenant_id: Option<&'a str>,
    session_id: Option<&'a str>,
    auth_method: &'a str,
    source: &'a str,
    client_ip: Option<&'a str>,
    user_agent: Option<&'a str>,
    request_id: Option<&'a str>,
    connection_id: Option<&'a str>,
    connection_name: Option<&'a str>,
    database: Option<&'a str>,
    schema_name: Option<&'a str>,
    operation: &'a str,
    sql_text: Option<&'a str>,
    sql_digest: Option<&'a str>,
    risk_level: Option<&'a str>,
    decision: &'a str,
    rule_id: Option<&'a str>,
    policy_version: Option<i64>,
    approval_id: Option<&'a str>,
    outcome: &'a str,
    error_code: Option<&'a str>,
    error_message: Option<&'a str>,
    affected_rows: Option<i64>,
    duration_ms: Option<i64>,
    details_json: Option<&'a str>,
}

fn compute_event_hash(
    event: &AuditEventInsert,
    seq: i64,
    prev_hash: &str,
    occurred_at_ms: i64,
    hash_scheme: &str,
) -> Result<String, String> {
    let canonical = CanonicalEvent {
        version: hash_scheme,
        chain_id: CHAIN_ID,
        seq,
        prev_hash,
        event_id: &event.event_id,
        occurred_at: &event.occurred_at,
        actor_id: &event.actor.id,
        actor_display_name: &event.actor.display_name,
        actor_kind: event.actor.kind.as_str(),
        actor_roles: &event.actor.roles,
        tenant_id: event.actor.tenant_id.as_deref(),
        session_id: event.actor.session_id.as_deref(),
        auth_method: &event.actor.auth_method,
        source: event.source.as_str(),
        client_ip: event.client_ip.as_deref(),
        user_agent: event.user_agent.as_deref(),
        request_id: event.request_id.as_deref(),
        connection_id: event.connection_id.as_deref(),
        connection_name: event.connection_name.as_deref(),
        database: event.database.as_deref(),
        schema_name: event.schema_name.as_deref(),
        operation: event.operation.as_str(),
        sql_text: event.sql_text.as_deref(),
        sql_digest: event.sql_digest.as_deref(),
        risk_level: event.risk_level.as_deref(),
        decision: event.decision.as_str(),
        rule_id: event.rule_id.as_deref(),
        policy_version: event.policy_version,
        approval_id: event.approval_id.as_deref(),
        outcome: event.outcome.as_str(),
        error_code: event.error_code.as_deref(),
        error_message: event.error_message.as_deref(),
        affected_rows: event.affected_rows,
        duration_ms: event.duration_ms,
        details_json: event.details_json.as_deref(),
    };
    let bytes = match hash_scheme {
        // Frozen: byte-for-byte the form written before scheme v2 existed.
        HASH_SCHEME_V1 => serde_json::to_vec(&canonical),
        HASH_SCHEME_V2 => serde_json::to_vec(&CanonicalEventV2 {
            base: canonical,
            occurred_at_ms,
            hash_scheme,
            event_type: &event.event_type,
            resource_type: event.resource_type.as_deref(),
            resource_id: event.resource_id.as_deref(),
            table_name: event.table_name.as_deref(),
            statement_index: event.statement_index,
            execution_id: event.execution_id.as_deref(),
            request_method: event.request_method.as_deref(),
            request_path: event.request_path.as_deref(),
            http_status: event.http_status,
            redaction_mode: event.redaction_mode.as_deref(),
            sql_fingerprint: event.sql_fingerprint.as_deref(),
            matched_rule_ids: &event.matched_rule_ids,
            policy_bundle_hash: event.policy_bundle_hash.as_deref(),
            actor_verified: event.actor_verified,
            on_behalf_of: event.on_behalf_of.as_deref(),
            delegated_by: event.delegated_by.as_deref(),
        }),
        other => return Err(format!("AUDIT_UNKNOWN_HASH_SCHEME: {other}")),
    }
    .map_err(|error| error.to_string())?;
    Ok(hex_sha256(&bytes))
}

/// V2 canonical form. `#[serde(flatten)]` keeps the v1 field order and
/// appends the new fields, so the bytes stay reproducible across builds.
///
/// The extended fields are part of the hash: an event's table, execution and
/// redaction metadata must be as tamper-evident as its SQL text. Adding a
/// field here afterwards requires a v3 scheme.
#[derive(serde::Serialize)]
struct CanonicalEventV2<'a> {
    #[serde(flatten)]
    base: CanonicalEvent<'a>,
    occurred_at_ms: i64,
    hash_scheme: &'a str,
    event_type: &'a str,
    resource_type: Option<&'a str>,
    resource_id: Option<&'a str>,
    table_name: Option<&'a str>,
    statement_index: Option<i64>,
    execution_id: Option<&'a str>,
    request_method: Option<&'a str>,
    request_path: Option<&'a str>,
    http_status: Option<i64>,
    redaction_mode: Option<&'a str>,
    sql_fingerprint: Option<&'a str>,
    matched_rule_ids: &'a [String],
    policy_bundle_hash: Option<&'a str>,
    actor_verified: bool,
    on_behalf_of: Option<&'a str>,
    delegated_by: Option<&'a str>,
}

fn genesis_hash(chain_id: &str) -> String {
    hex_sha256(format!("dbx-audit-v1:genesis:{chain_id}").as_bytes())
}

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

fn now_rfc3339() -> String {
    Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// Escapes LIKE wildcards so a search for `100%` matches the literal text.
fn like_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' | '%' | '_' => {
                escaped.push('\\');
                escaped.push(character);
            }
            other => escaped.push(other),
        }
    }
    escaped
}

#[cfg(all(test, feature = "enterprise-audit"))]
mod tests {
    use super::*;
    use crate::audit::{AuditContext, AuditDecision, AuditOperation, AuditOutcome, AuditSource};

    fn event(id: &str, sql: &str) -> AuditEventInsert {
        let context = AuditContext {
            actor: Actor::bootstrap(),
            source: AuditSource::Web,
            client_ip: Some("127.0.0.1".to_string()),
            user_agent: Some("test".to_string()),
            request_id: Some(format!("req-{id}")),
            execution_id: Some(format!("exec-{id}")),
        };
        let mut event =
            AuditEventInsert::new(&context, AuditOperation::Query, AuditDecision::Allowed, AuditOutcome::Success);
        event.event_id = id.to_string();
        event.sql_text = Some(sql.to_string());
        event.sql_digest = Some(hex_sha256(sql.as_bytes()));
        event
    }

    async fn storage() -> (Storage, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!("dbx-audit-{}.db", uuid::Uuid::new_v4()));
        (crate::persistence::test_storage::open(&path).await.unwrap(), path)
    }

    #[tokio::test]
    async fn append_only_rejects_update_and_delete() {
        let (storage, _) = storage().await;
        let inserted = storage.insert_audit_event(event("e1", "SELECT 1")).await.unwrap();
        let seq = inserted.seq;
        let update = storage
            .with_conn(move |conn| {
                conn.execute("UPDATE audit_events SET sql_text = 'SELECT 2' WHERE seq = ?1", [seq])
                    .map_err(|error| error.to_string())
            })
            .await;
        assert!(update.is_err(), "append-only trigger must reject UPDATE");
        let delete = storage
            .with_conn(move |conn| {
                conn.execute("DELETE FROM audit_events WHERE seq = ?1", [seq]).map_err(|error| error.to_string())
            })
            .await;
        assert!(delete.is_err(), "append-only trigger must reject DELETE");
    }

    #[tokio::test]
    async fn hash_chain_detects_tamper() {
        let (storage, _) = storage().await;
        for index in 1..=3 {
            storage.insert_audit_event(event(&format!("e{index}"), &format!("SELECT {index}"))).await.unwrap();
        }
        let report = storage.verify_audit_chain(None, None).await.unwrap();
        assert_eq!(report.checked, 3);
        assert_eq!(report.first_broken_seq, None);
        assert_eq!(report.head_seq, 3);

        storage
            .with_conn(|conn| {
                conn.execute_batch(
                    "DROP TRIGGER audit_events_no_update; \
                     UPDATE audit_events SET sql_text = 'SELECT 99' WHERE seq = 2;",
                )
                .map_err(|error| error.to_string())
            })
            .await
            .unwrap();
        let report = storage.verify_audit_chain(None, None).await.unwrap();
        assert_eq!(report.first_broken_seq, Some(2));
    }

    #[tokio::test]
    async fn chain_survives_reopen_and_duplicate_event_id_is_rejected() {
        let (storage, path) = storage().await;
        storage.insert_audit_event(event("e1", "SELECT 1")).await.unwrap();
        drop(storage);
        let reopened = crate::persistence::test_storage::open(&path).await.unwrap();
        assert_eq!(reopened.verify_audit_chain(None, None).await.unwrap().checked, 1);
        let duplicate = reopened.insert_audit_event(event("e1", "SELECT 2")).await;
        assert!(duplicate.is_err(), "event_id is the idempotency key");
        let second = reopened.insert_audit_event(event("e2", "SELECT 2")).await.unwrap();
        assert_eq!(second.seq, 2);
        assert_eq!(reopened.verify_audit_chain(None, None).await.unwrap().checked, 2);
    }

    #[tokio::test]
    async fn cursor_query_returns_newest_first_and_batch_inserts_one_transaction() {
        let (storage, _) = storage().await;
        let inserted =
            storage.insert_audit_events_batch(vec![event("e1", "SELECT 1"), event("e2", "SELECT 2")]).await.unwrap();
        assert_eq!(inserted.iter().map(|event| event.seq).collect::<Vec<_>>(), vec![1, 2]);
        storage.insert_audit_event(event("e3", "SELECT 3")).await.unwrap();

        let page = storage.query_audit_events(AuditQuery { limit: Some(2), ..Default::default() }).await.unwrap();
        assert_eq!(page.events.iter().map(|event| event.seq).collect::<Vec<_>>(), vec![3, 2]);
        assert_eq!(page.next_cursor, Some(2));

        let page = storage
            .query_audit_events(AuditQuery { limit: Some(2), cursor_seq: page.next_cursor, ..Default::default() })
            .await
            .unwrap();
        assert_eq!(page.events.iter().map(|event| event.seq).collect::<Vec<_>>(), vec![1]);
        assert_eq!(page.next_cursor, None);
    }

    #[tokio::test]
    async fn query_filters_by_decision_and_chain_head_matches_last_event() {
        let (storage, _) = storage().await;
        storage.insert_audit_event(event("e1", "SELECT 1")).await.unwrap();
        let mut denied = event("e2", "DROP TABLE users");
        denied.decision = AuditDecision::Denied;
        denied.actor.id = "other".to_string();
        let second = storage.insert_audit_event(denied).await.unwrap();

        let page = storage
            .query_audit_events(AuditQuery { decision: Some(AuditDecision::Denied), ..Default::default() })
            .await
            .unwrap();
        assert_eq!(page.events.len(), 1);
        assert_eq!(page.events[0].event.event_id, "e2");

        let head = storage.audit_chain_head().await.unwrap();
        assert_eq!(head.last_seq, second.seq);
        assert_eq!(head.last_hash, second.event_hash);
    }

    #[tokio::test]
    async fn verify_detects_tail_truncation() {
        let (storage, _) = storage().await;
        for index in 1..=3 {
            storage.insert_audit_event(event(&format!("e{index}"), &format!("SELECT {index}"))).await.unwrap();
        }
        storage
            .with_conn(|conn| {
                conn.execute_batch("DROP TRIGGER audit_events_no_delete; DELETE FROM audit_events WHERE seq = 3;")
                    .map_err(|error| error.to_string())
            })
            .await
            .unwrap();

        let report = storage.verify_audit_chain(None, None).await.unwrap();
        assert_eq!(report.checked, 2);
        assert_eq!(report.first_broken_seq, Some(3), "a deleted tail must not verify cleanly");
    }

    #[tokio::test]
    async fn verify_detects_a_missing_middle_row() {
        let (storage, _) = storage().await;
        for index in 1..=3 {
            storage.insert_audit_event(event(&format!("e{index}"), &format!("SELECT {index}"))).await.unwrap();
        }
        storage
            .with_conn(|conn| {
                conn.execute_batch("DROP TRIGGER audit_events_no_delete; DELETE FROM audit_events WHERE seq = 2;")
                    .map_err(|error| error.to_string())
            })
            .await
            .unwrap();

        let report = storage.verify_audit_chain(None, None).await.unwrap();
        assert_eq!(report.checked, 1);
        assert_eq!(report.first_broken_seq, Some(2), "a gap must be reported at the missing seq");
    }

    #[tokio::test]
    async fn verify_detects_a_rolled_back_head() {
        let (storage, _) = storage().await;
        for index in 1..=3 {
            storage.insert_audit_event(event(&format!("e{index}"), &format!("SELECT {index}"))).await.unwrap();
        }
        let second_hash: String = storage
            .with_conn(|conn| {
                conn.query_row("SELECT event_hash FROM audit_events WHERE seq = 2", [], |row| row.get(0))
                    .map_err(|error| error.to_string())
            })
            .await
            .unwrap();
        storage
            .with_conn(move |conn| {
                conn.execute_batch("DROP TRIGGER audit_chain_head_monotonic;")
                    .map_err(|error| error.to_string())?;
                conn.execute(
                    "UPDATE audit_chain_head SET last_seq = 2, last_hash = ?1, event_count = 2 WHERE chain_id = 'default'",
                    [&second_hash],
                )
                .map_err(|error| error.to_string())?;
                Ok(())
            })
            .await
            .unwrap();

        let report = storage.verify_audit_chain(None, None).await.unwrap();
        assert_eq!(report.first_broken_seq, Some(3), "rows above a rolled-back head must be detected");
    }

    #[tokio::test]
    async fn verify_reports_a_deleted_head_and_refuses_to_reseed_it() {
        let (storage, _) = storage().await;
        storage.insert_audit_event(event("e1", "SELECT 1")).await.unwrap();
        storage
            .with_conn(|conn| {
                conn.execute_batch("DROP TRIGGER audit_chain_head_no_delete; DELETE FROM audit_chain_head;")
                    .map_err(|error| error.to_string())
            })
            .await
            .unwrap();

        assert!(storage.verify_audit_chain(None, None).await.is_err());
        let reseed = storage.with_conn(|conn| ensure_audit_schema_sync(conn)).await;
        assert!(reseed.is_err(), "a non-empty chain must never be silently reseeded at genesis");
    }

    #[tokio::test]
    async fn a_checkpoint_anchors_the_tail_it_covers() {
        let (storage, _) = storage().await;
        for index in 1..=3 {
            storage.insert_audit_event(event(&format!("e{index}"), &format!("SELECT {index}"))).await.unwrap();
        }
        let checkpoint = storage.create_audit_checkpoint().await.unwrap();
        assert_eq!(checkpoint.seq, 3);
        let head = storage.audit_chain_head().await.unwrap();
        assert_eq!(checkpoint.event_hash, head.last_hash);

        let report = storage.verify_audit_chain_from_checkpoint().await.unwrap();
        assert_eq!(report.checkpoint.unwrap().seq, 3);
        assert_eq!(report.report.first_broken_seq, None);

        storage.insert_audit_event(event("e4", "SELECT 4")).await.unwrap();
        let report = storage.verify_audit_chain_from_checkpoint().await.unwrap();
        assert_eq!(report.report.checked, 1, "only the tail after the checkpoint is re-verified");
        assert_eq!(report.report.first_broken_seq, None);
    }

    #[tokio::test]
    async fn a_checkpoint_detects_that_its_own_row_was_replaced() {
        let (storage, _) = storage().await;
        for index in 1..=3 {
            storage.insert_audit_event(event(&format!("e{index}"), &format!("SELECT {index}"))).await.unwrap();
        }
        storage.create_audit_checkpoint().await.unwrap();
        storage
            .with_conn(|conn| {
                conn.execute_batch(
                    "DROP TRIGGER audit_events_no_update; \
                     UPDATE audit_events SET event_hash = 'rewritten' WHERE seq = 3;",
                )
                .map_err(|error| error.to_string())
            })
            .await
            .unwrap();

        let report = storage.verify_audit_chain_from_checkpoint().await.unwrap();
        assert_eq!(report.report.first_broken_seq, Some(3));
    }

    #[tokio::test]
    async fn checkpoints_are_immutable() {
        let (storage, _) = storage().await;
        storage.insert_audit_event(event("e1", "SELECT 1")).await.unwrap();
        storage.create_audit_checkpoint().await.unwrap();

        let update = storage
            .with_conn(|conn| {
                conn.execute("UPDATE audit_checkpoints SET event_hash = 'x'", []).map_err(|error| error.to_string())
            })
            .await;
        assert!(update.is_err(), "a checkpoint must not be rewritable");
        let delete = storage
            .with_conn(|conn| conn.execute("DELETE FROM audit_checkpoints", []).map_err(|error| error.to_string()))
            .await;
        assert!(delete.is_err(), "a checkpoint must not be deletable");
    }

    #[tokio::test]
    async fn without_a_checkpoint_the_whole_chain_is_verified() {
        let (storage, _) = storage().await;
        storage.insert_audit_event(event("e1", "SELECT 1")).await.unwrap();
        let report = storage.verify_audit_chain_from_checkpoint().await.unwrap();
        assert!(report.checkpoint.is_none());
        assert_eq!(report.report.checked, 1);
        assert_eq!(report.report.first_broken_seq, None);
    }

    #[tokio::test]
    async fn an_attached_audit_database_is_used_instead_of_the_business_db() {
        let (storage, business_path) = storage().await;
        let audit_path = business_path.with_file_name(format!("audit-{}.db", uuid::Uuid::new_v4()));
        storage.attach_audit_database(&audit_path).await.unwrap();
        storage.insert_audit_event(event("e1", "SELECT 1")).await.unwrap();
        assert_eq!(storage.verify_audit_chain(None, None).await.unwrap().checked, 1);

        let business = rusqlite::Connection::open(&business_path).unwrap();
        let business_rows: i64 = business.query_row("SELECT COUNT(*) FROM audit_events", [], |row| row.get(0)).unwrap();
        assert_eq!(business_rows, 0, "audit rows must not land in the business database");

        let dedicated = rusqlite::Connection::open(&audit_path).unwrap();
        let dedicated_rows: i64 =
            dedicated.query_row("SELECT COUNT(*) FROM audit_events", [], |row| row.get(0)).unwrap();
        assert_eq!(dedicated_rows, 1);
    }

    #[tokio::test]
    async fn pruning_requires_a_covering_checkpoint_and_export() {
        let (storage, _) = storage().await;
        for index in 1..=3 {
            storage.insert_audit_event(event(&format!("e{index}"), &format!("SELECT {index}"))).await.unwrap();
        }
        assert_eq!(
            storage.prune_audit_events(1, "admin".into(), "test".into()).await.unwrap_err(),
            "AUDIT_PRUNE_CHECKPOINT_REQUIRED"
        );
        storage.create_audit_checkpoint().await.unwrap();
        assert_eq!(
            storage.prune_audit_events(1, "admin".into(), "test".into()).await.unwrap_err(),
            "AUDIT_PRUNE_EXPORT_REQUIRED"
        );
        storage.set_audit_export_state("http_jsonl".to_string(), 2).await.unwrap();
        assert_eq!(storage.prune_audit_events(1, "admin".into(), "test".into()).await.unwrap(), 1);

        // Verification now starts from the retained floor instead of seq 1.
        let report = storage.verify_audit_chain(None, None).await.unwrap();
        assert_eq!(report.first_broken_seq, None);
        assert_eq!(report.checked, 2);

        storage.insert_audit_event(event("e4", "SELECT 4")).await.unwrap();
        let report = storage.verify_audit_chain(None, None).await.unwrap();
        assert_eq!(report.checked, 3);
        assert_eq!(report.first_broken_seq, None);
    }

    #[tokio::test]
    async fn pruning_refuses_the_live_tail_and_repeats() {
        let (storage, _) = storage().await;
        for index in 1..=2 {
            storage.insert_audit_event(event(&format!("e{index}"), &format!("SELECT {index}"))).await.unwrap();
        }
        storage.create_audit_checkpoint().await.unwrap();
        storage.set_audit_export_state("http_jsonl".to_string(), 2).await.unwrap();
        assert_eq!(
            storage.prune_audit_events(2, "admin".into(), "tail".into()).await.unwrap_err(),
            "AUDIT_PRUNE_RANGE_INVALID"
        );
        storage.prune_audit_events(1, "admin".into(), "ok".into()).await.unwrap();
        assert_eq!(
            storage.prune_audit_events(1, "admin".into(), "again".into()).await.unwrap_err(),
            "AUDIT_PRUNE_ALREADY_PRUNED"
        );
    }

    #[tokio::test]
    async fn chain_head_rejects_delete_and_non_advancing_updates() {
        let (storage, _) = storage().await;
        storage.insert_audit_event(event("e1", "SELECT 1")).await.unwrap();

        let update = storage
            .with_conn(|conn| {
                conn.execute("UPDATE audit_chain_head SET last_seq = 5 WHERE chain_id = 'default'", [])
                    .map_err(|error| error.to_string())
            })
            .await;
        assert!(update.is_err(), "head updates must advance exactly one seq");

        let delete = storage
            .with_conn(|conn| {
                conn.execute("DELETE FROM audit_chain_head WHERE chain_id = 'default'", [])
                    .map_err(|error| error.to_string())
            })
            .await;
        assert!(delete.is_err(), "the head must not be deletable");
    }

    #[tokio::test]
    async fn a_v1_row_still_verifies_under_a_v2_chain() {
        let (storage, _) = storage().await;
        // Simulate an upgrade: the first row was written by the previous
        // binary under the frozen v1 canonical form, the rest by this one.
        storage.insert_audit_event_with_scheme(event("legacy", "SELECT 0"), HASH_SCHEME_V1).await.unwrap();
        storage.insert_audit_event(event("e2", "SELECT 2")).await.unwrap();
        storage.insert_audit_event(event("e3", "SELECT 3")).await.unwrap();

        let report = storage.verify_audit_chain(None, None).await.unwrap();
        assert_eq!(report.first_broken_seq, None);
        assert_eq!(report.checked, 3);
        assert_eq!(report.head_seq, 3);

        // Tampering with the legacy row must still be detected.
        storage
            .with_conn(|conn| {
                conn.execute_batch(
                    "DROP TRIGGER audit_events_no_update; \
                     UPDATE audit_events SET sql_text = 'SELECT 99' WHERE seq = 1;",
                )
                .map_err(|error| error.to_string())
            })
            .await
            .unwrap();
        let report = storage.verify_audit_chain(None, None).await.unwrap();
        assert_eq!(report.first_broken_seq, Some(1));
    }

    #[tokio::test]
    async fn an_unknown_hash_scheme_is_reported_as_a_break_not_an_error() {
        let (storage, _) = storage().await;
        storage.insert_audit_event(event("e1", "SELECT 1")).await.unwrap();
        storage
            .with_conn(|conn| {
                conn.execute_batch(
                    "DROP TRIGGER audit_events_no_update; \
                     UPDATE audit_events SET hash_scheme = 'sha256-v9' WHERE seq = 1;",
                )
                .map_err(|error| error.to_string())
            })
            .await
            .unwrap();

        let report = storage.verify_audit_chain(None, None).await.unwrap();
        assert_eq!(report.first_broken_seq, Some(1));
    }

    #[tokio::test]
    async fn new_rows_are_written_with_the_current_scheme() {
        let (storage, _) = storage().await;
        storage.insert_audit_event(event("e1", "SELECT 1")).await.unwrap();
        let scheme: String = storage
            .with_conn(|conn| {
                conn.query_row("SELECT hash_scheme FROM audit_events WHERE seq = 1", [], |row| row.get(0))
                    .map_err(|error| error.to_string())
            })
            .await
            .unwrap();
        assert_eq!(scheme, CURRENT_HASH_SCHEME);
        assert_ne!(HASH_SCHEME_V1, CURRENT_HASH_SCHEME);
    }
}
