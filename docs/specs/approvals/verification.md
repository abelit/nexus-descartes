# Approvals: verification

## Automated

```bash
RUST_MIN_STACK=8388608 cargo test -p dbx-core --features enterprise-audit --lib governance::approval
RUST_MIN_STACK=8388608 cargo test -p dbx-core --features enterprise-audit --lib persistence::storage::approval
cargo check -p dbx-web --features enterprise-audit --bin dbx-web
```

Covered:

- the binding hash is stable, rule-order insensitive (deduplicated), and changes
  when the connection config hash, database, schema, statement digest, policy
  bundle, or rule set changes;
- the statement digest changes when a character of SQL changes;
- a token only authorizes its own actor and binding, expires, and can be
  consumed once;
- a fresh token returns the raw secret and its 64-character hash;
- a request round-trips through storage, only one decision wins, listing filters
  by requester and status, and token consumption is single-use.

## Manual

1. With `DBX_GOVERNANCE_MODE=enforce`, run a production `ALTER TABLE` →
   `POLICY_APPROVAL_REQUIRED`.
2. `POST /api/approvals` with that SQL → pending request listing the rule
   `prod.ddl.approval`.
3. As the requester, `POST /api/approvals/{id}/approve` → 403
   `APPROVAL_SELF_DECISION`; as a DBA, approve → `approved`.
4. As the requester, request the execute token → raw token returned once; a
   second request returns a different token; the first expires after 5 minutes.
5. Edit the SQL and try to use the token → `APPROVAL_TOKEN_BINDING_MISMATCH`.

## Known gaps

- Approval tokens are consumed by the single-statement funnel only; batch and
  manual-transaction paths still stop at `APPROVAL_REQUIRED`.
- No notification, multi-step or countersign flows; the UI is a flat list.
- `policy_bundle_hash` is not populated until stored policies exist.
