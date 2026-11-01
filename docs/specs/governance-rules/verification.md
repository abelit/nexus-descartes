# Governance rules and hilbert identity: verification

## Automated

```bash
RUST_MIN_STACK=8388608 cargo test -p dbx-core --features enterprise-audit --lib governance
RUST_MIN_STACK=8388608 cargo test -p dbx-core --features enterprise-audit --lib identity::hilbert
cargo check -p dbx-web --features enterprise-audit --bin dbx-web
node scripts/check-governed-sql.mjs
```

Rule tests cover: SELECT allowed; production DDL requires approval; the same
DDL outside production only warns; an unbounded production write is blocked and
a bounded one is allowed; `TRUNCATE` and privilege changes require approval; the
strictest matched effect wins while every match is reported; purpose labels map
to audit operations and generated SQL is capped at 64 KiB.

hilbert tests cover: a valid access token verifies and maps `operator`; refresh
tokens, missing token types, wrong audience, wrong issuer, expired tokens, and a
foreign signature are rejected; HS256 without the explicit transition flag is
refused; superusers map to `admin` and unknown roles to `viewer`.

The generated-SQL guard writes/compares `scripts/governed-sql-baseline.json`
and fails when a file gains a direct driver call without going through
`governance::execute_generated_sql`.

## Manual

1. `DBX_GOVERNANCE_MODE=enforce`, production connection:
   `DELETE FROM users` → `POLICY_DENIED`; an `ALTER TABLE` → `POLICY_APPROVAL_REQUIRED`;
   either attempt appears in `/api/audit/events` with the matching decision.
2. Simulate first: the response lists `prod.dml.no_where.block` and
   `global.no_where.warn` for the same statement.
3. With `DBX_HILBERT_ENABLED=1` and an RS256 public key, call any API with
   `Authorization: Bearer <access token>`; the audit actor is
   `hilbert:<subject>` and the mapped role is applied. A refresh token returns
   401.

## Known gaps

- Only the single-statement funnel enforces rules; batch, transaction, and
  manual-transaction paths still execute in observe mode even when enforcement
  is on.
- Hilber tokens are not cached: every request verifies the signature again.
- Approval decisions (`require_approval`) have no ticket flow yet.
