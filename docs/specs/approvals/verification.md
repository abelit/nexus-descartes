# Approvals: verification

## Automated

```bash
RUST_MIN_STACK=8388608 cargo test -p dbx-core --features enterprise-audit --lib governance::approval
RUST_MIN_STACK=8388608 cargo test -p dbx-core --features enterprise-audit --lib persistence::storage::approval
cargo check -p dbx-web --features enterprise-audit --bin dbx-web
scripts/e2e-governance.sh   # Docker PostgreSQL + MySQL end-to-end
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
  by requester and status, and token consumption is single-use;
- `any` steps complete on one approval and advance `current_step_no`; the last
  step approves the request;
- `all` steps stay open until every snapshotted approver approves, and a user
  cannot vote twice on the same step;
- a rejection rejects the request and marks later steps `skipped`;
- only a user in the step's creation-time approver snapshot can vote; a role
  granted after the request opened does not widen it, and a snapshot member can
  still vote after losing the role;
- the requester is removed from the approver snapshot, and a step with no other
  approver fails creation with `APPROVAL_STEP_NO_APPROVER`;
- template documents validation, connection-over-global resolution, and
  one-template-per-scope replacement;
- execution modes parse DMS aliases (`commitor`, `last_auditor`), default to
  `submitter`, and mark `auto`/`last_approver` as requiring a saved credential;
- an approved request can be claimed for execution exactly once
  (`approved -> executing -> executed`), a second claim fails, and a binding
  failure moves it to `execution_failed` with the stored error;
- `scripts/e2e-governance.sh` runs the whole flow against real PostgreSQL and
  MySQL containers: SQL on both drivers, 403 `POLICY_APPROVAL_REQUIRED` before
  approval, multi-step/countersign decisions, snapshot membership, server-side
  execution of the stored request, one-execution enforcement, `auto` mode after
  the last approval, token execution for an external client, audit chain
  verification, and rows in the PostgreSQL audit sink.

## Manual

1. With `DBX_GOVERNANCE_MODE=enforce`, run a production `ALTER TABLE` →
   `POLICY_APPROVAL_REQUIRED`.
2. `POST /api/approvals` with that SQL → pending request listing the rule
   `prod.ddl.approval`.
3. Publish a two-step template with `any` then `all`; create a second request →
   it shows `step_count: 2`.
4. As the requester, `POST /api/approvals/{id}/approve` → 403
   `APPROVAL_SELF_DECISION`; as the first approver, approve → the request stays
   `pending` with `current_step_no: 2`; approving the same step twice →
   `APPROVAL_ALREADY_DECIDED`.
5. `GET /api/approvals/{id}` shows the step timeline and recorded votes; an
   unrelated user gets `APPROVAL_FORBIDDEN`.
6. Complete the last step → `approved`; as the requester,
   `POST /api/approvals/{id}/execute` → `executed`, and the table exists in the
   target database. A second call → 409 `APPROVAL_ALREADY_EXECUTED`.
7. Create a request with `execution_mode: "auto"` (connection saved password),
   approve all steps → the request moves to `executing` and then `executed`
   without another client call. With `save_password=false`, creation fails with
   `APPROVAL_EXECUTION_MODE_REQUIRES_SAVED_CREDENTIAL`.
8. As the requester, request the execute token → raw token returned once; a
   second request returns a different token; the first expires after 5 minutes.
   Edit the SQL and try to use the token → `APPROVAL_TOKEN_BINDING_MISMATCH`.
9. Reject a request at step 1 → status `rejected`, step 2 `skipped`.

## Known gaps

- Approval tokens are consumed by the single-statement funnel, script/batch
  execution, and explicit `use_transaction` batches; manual transactions still
  stop at `APPROVAL_REQUIRED`.
- Notifications cover the generic webhook plus DingTalk and Feishu/Lark bots
  (signing included); email needs an SMTP bridge in front of the webhook. SLA
  reminders, scheduled execution, and break-glass overrides are not implemented.
- Role membership is snapshotted at request creation. A countersign whose
  snapshot members are all disabled stays pending until an administrator
  cancels and reissues it; there is no reassignment flow yet.
- `policy_bundle_hash` is not populated until stored policies exist.
