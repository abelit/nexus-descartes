# Enterprise audit: verification

## Automated

```bash
cargo test -p dbx-core --features enterprise-audit --lib audit
cargo check -p dbx-web --features enterprise-audit --bin dbx-web
cargo check -p dbx-web --features enterprise-audit --tests
NODE_OPTIONS=--max-old-space-size=8192 pnpm typecheck
pnpm vitest run apps/desktop/src/lib/settings apps/desktop/src/i18n/__tests__/localePlaceholderParity.spec.ts
scripts/e2e-governance.sh   # also asserts chain verification and the PostgreSQL sink
```

`dbx-core` audit suite (45 tests) covers:

- chain: tamper of a middle row, tail truncation, missing middle row,
  rolled-back head, deleted head with refusal to re-seed, head delete and
  non-advancing update rejection;
- schemes: a `sha256-v1` row verifying inside a `sha256-v2` chain, tamper of the
  legacy row still detected, unknown scheme reported as a break rather than an
  error, new rows written with the current scheme;
- every audit source (including `approval`, used by DMS-style execution)
  round-trips through storage and chain verification; a source the verifier
  cannot parse would otherwise recompute a different hash and report a false
  break;
- checkpoints: anchor matches the head, tail-only verification after the
  anchor, replaced anchored row detected, checkpoint update/delete rejected,
  genesis verification when no checkpoint exists;
- durability: `append_durable` commits before returning, `NoopAuditSink` is not
  durable, memory sink is, queue backpressure is reported, batch order and
  counters preserved;
- retention: credential masking for `IDENTIFIED BY`, `SET PASSWORD`,
  `scheme://user:pass@host`, Redis `AUTH`; masking leaves the approval digest
  untouched; digest mode stores no text; fingerprint normalizes literals but not
  identifiers;
- batch: per-statement events when the driver reports results, one summary
  event with `statement_count` when it does not, no events without a context.

Signature: HMAC-SHA256 validated against RFC 4231 test cases 1, 2, and the
long-key case.

## Manual (Docker + a test database)

1. `DBX_AUDIT_BOOTSTRAP_TOKEN=... DBX_PASSWORD=test cargo run -p dbx-web`
2. Run a query, a script (`/api/query/execute-script`), a transaction, and a
   MySQL multi-statement batch. `GET /api/audit/events` shows one event per
   statement, or one batch event where the driver returns a summary.
3. `POST /api/audit/checkpoint`, then `GET /api/audit/verify-checkpoint` →
   `first_broken_seq = null`.
4. Tamper with a row using a separate SQLite client (dropping the trigger),
   then `GET /api/audit/verify` → the sequence is reported.
5. Stop the process with SIGTERM; every event accepted before shutdown is
   present after restart (queue flush).
6. `GET /api/audit/export?format=csv` — cells beginning with `=`, `+`, `-`, `@`
   are prefixed with `'`.

## End-to-end smoke (2026-11-02, local binary)

Ran `dbx-web` with `DBX_PASSWORD`, `DBX_AUDIT_BOOTSTRAP_TOKEN`,
`DBX_GOVERNANCE_MODE=enforce`, `DBX_AUDIT_ALLOW_PRUNE=1` and an empty data dir:

- login → `admin` actor with all permission codes; viewer user shows only
  `connection:read`/`query:read`;
- audit API: bootstrap token without a session → 200 (attributed to `system`),
  wrong token → 401, viewer session → 403;
- publishing a global `block` rule changed `policy_bundle_hash`;
- checkpoint creation → 200; `verify-checkpoint` clean;
- prune without an export → 400 `AUDIT_PRUNE_CHECKPOINT_REQUIRED`/`EXPORT_REQUIRED`;
  after recording an export cursor → 200 `deleted: 1`, floor = deleted seq,
  `verify` re-checked the remaining chain with no break;
- `audit.db` exists with all rows while `dbx.db` has zero `audit_events`.

## Known gaps

- Direct driver calls in `schema/*`, `data/table_import.rs`, `sql_file_import.rs`
  and export paths are not yet statement-audited; the HTTP middleware records
  the operation.
- Local MCP and the CLI install a sink through `LocalBackend` and record with
  `source=mcp` / `source=cli`; the desktop installs a sink and flushes on exit.
- External export supports signed HTTP JSON and a PostgreSQL sink (TLS, one row
  per event, `ON CONFLICT DO NOTHING`). SLS/OSS ingestion is expected through a
  collector behind the HTTP sink. Segment deletion exists as an explicit,
  dual-gated prune (checkpoint + export), never automatic.
- Audit access is gated by session roles (`audit:read` / `audit:export` /
  `audit:verify`); the bootstrap token or loopback remains as the automation
  fallback until the first local user logs in.
