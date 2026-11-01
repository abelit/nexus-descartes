# Enterprise audit: trustworthy server-side operation log

Issue: enterprise audit / access governance (DMS-style). Tracking plan:
`.claude/plans/dms-dbx-mutable-bear.md`.

Approval: the user approved the A–D plan in this conversation and confirmed the
Web/Docker server as the enforcement boundary, local multi-user plus hilbert JWT
identity, `full` SQL retention by default, and delivery of the full phase set.

## Scope and acceptance

- Audit events are written by the server, append-only, and chained with
  SHA-256. `GET /api/audit/verify` must report each of: a modified row, a deleted
  tail, a rolled-back head, a deleted head, and a missing middle row.
- The canonical hash form is versioned. Rows written with `sha256-v1` keep
  verifying after the `sha256-v2` form (which adds `occurred_at_ms`,
  `hash_scheme`, and the extended event columns) starts being written.
- `audit_chain_head` is protected by triggers and is never re-seeded while
  events exist.
- Fail-closed recording must have a real durability contract:
  `AuditSink::append_durable` returns only after commit, `NoopAuditSink` is
  never durable, and process shutdown flushes the queue before exit.
- A failed batch write must be retried, not dropped.
- Every user SQL path records an event: single statement, MySQL and SQL Server
  batch fast paths, scripts, explicit transactions, and manual transactions.
  A driver that only returns a summary produces one batch event with
  `statement_count`, never fabricated per-statement rows.
- Non-SQL mutations (schema, import, export, settings) are recorded by an HTTP
  middleware; SQL and HTTP events share `request_id` for correlation.
- Statement retention is `full` by default with credential literals masked;
  `redacted` and `digest` are available. The digest used for approval binding is
  always computed from the raw statement.
- The Web server writes the log to a dedicated SQLite database
  (`DBX_AUDIT_DB_PATH`, default `<data_dir>/audit.db`); desktop/CLI/MCP keep it
  in their existing database.
- Hourly checkpoints anchor the head. Signing uses `DBX_AUDIT_CHECKPOINT_KEY`
  (HMAC-SHA256); verification can start from the newest checkpoint.
- Until roles exist, the audit API is gated by `DBX_AUDIT_BOOTSTRAP_TOKEN` or
  loopback, and login maps to the single `local:admin` actor with
  `actor_verified=false`; the operator label is only `details.hint`.

## External export (Phase E, first slice)

- `DBX_AUDIT_EXPORT_URL` pushes signed JSON envelopes every 10s: range, count,
  and the events. `x-dbx-audit-signature` is HMAC-SHA256 over the exact body.
- Delivery is at-least-once and resumes from `audit_export_state`; receivers
  deduplicate on `event_id`.
- Segment deletion stays manual; retention only warns.

## Non-goals

- Stored, versioned policy documents and approvals (next phases). The built-in
  high-risk rule set and `POST /api/governance/simulate` exist; route-level RBAC
  is implemented separately in the local-identity spec.
- Automatic deletion of audit segments: retention only warns until a copy is
  anchored outside the database.
- Auditing every direct driver call made by schema/import internals. The
  `governance::execute_generated_sql` choke and
  `scripts/check-governed-sql.mjs` (baseline of existing call sites) now exist;
  migrating the remaining baseline files is tracked separately.

## Data model

- `audit_events` (extended): `event_type`, `resource_type`, `resource_id`,
  `table_name`, `statement_index`, `execution_id`, `request_method`,
  `request_path`, `http_status`, `redaction_mode`, `sql_fingerprint`,
  `matched_rule_ids_json`, `policy_bundle_hash`, `actor_verified`,
  `on_behalf_of`, `delegated_by`, `hash_scheme`.
- `audit_chain_head`, `audit_checkpoints`, `audit_outbox`.
- Append-only triggers on `audit_events` and `audit_checkpoints`, monotonic
  head updates.

## API

`GET /api/audit/events`, `/events/:id`, `/stats`, `/chain-head`,
`/checkpoints`, `/verify`, `/verify-checkpoint`,
`POST /api/audit/checkpoint`, `GET /api/audit/export?format=jsonl|csv`.
