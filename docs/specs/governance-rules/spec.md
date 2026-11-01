# Governance rules and hilbert identity

Issue: enterprise audit / access governance, Phase C (first slice) and the
hilbert JWT adapter. Tracking plan: `.claude/plans/dms-dbx-mutable-bear.md`.

## Scope and acceptance

### High-risk rules

- Code-defined rule set with a fixed strictness order:
  `block > require_approval > warn > allow`.
- Rules: production DDL approval, unbounded production write block, production
  `TRUNCATE` approval, production privilege-change approval, global unbounded
  write warning, global DDL warning.
- Evaluation uses the existing AST classification
  (`classify_sql_risk_for_database`, `is_dangerous_sql_for_database`) and the
  connection's production marker (`is_production`,
  `production_databases`); it does not reimplement SQL parsing.
- `POST /api/governance/simulate` returns the decision and every matching rule
  without executing anything; requires `query:read`.
- With `DBX_GOVERNANCE_MODE=enforce`, a `block` decision fails with
  `POLICY_DENIED` and `require_approval` with `POLICY_APPROVAL_REQUIRED` before
  any driver call; audit records `blocked` / `approval_required`. `observe`
  (default) records nothing new and changes no behavior.

### hilbert tokens

- `Authorization: Bearer <token>` is accepted when `DBX_HILBERT_ENABLED=1`
  (verified on every request; no DBX session is created).
- Tokens must declare `aud=dbx`, `iss=ongrid`, and `token_type=access`;
  refresh tokens and missing token types are rejected.
- RS256 with a PEM public key is preferred. HS256 is refused unless
  `DBX_HILBERT_ALLOW_SHARED_SECRET=1`, because hilbert derives its vault key
  from `ONGRID_JWT_SECRET` when `ONGRID_SECRET_KEY` is unset.
- Role mapping is conservative until `/v1/me` memberships: superuser →
  `admin`; `admin|owner` → `admin`; known roles map to themselves; anything
  else → `viewer`.

### Generated SQL choke

- `governance::execute_generated_sql` records DBX-initiated SQL operations with
  a purpose label; `schema.sqlite_rebuild` is migrated as the first caller.
- `scripts/check-governed-sql.mjs` keeps a baseline of direct driver calls and
  fails when a new call appears; it runs inside `pnpm check`.

## Non-goals

- Stored, versioned policy documents and scope precedence (next slice).
- Approval tickets and one-time execution tokens (Phase D).
- `/v1/me` membership resolution and JWKS discovery.
- Migrating the remaining baseline files to `execute_generated_sql`.
