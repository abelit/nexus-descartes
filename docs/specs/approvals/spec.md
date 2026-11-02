# Approval requests and execution tokens

Issue: enterprise audit / access governance, Phase D. Tracking plan:
`.claude/plans/dms-dbx-mutable-bear.md`.

## Scope and acceptance

- A request is created only for a statement the built-in rules mark
  `require_approval`; otherwise creation fails with `APPROVAL_NOT_REQUIRED`.
- The request is bound to a deterministic hash over: connection ID, connection
  configuration hash, database, schema, ordered-statement digest, policy bundle
  hash, and the sorted rule IDs that required approval.
- One-time execution tokens store only a SHA-256 hash, carry the requester and
  the request hash, expire after 5 minutes, and are consumed atomically.
- The requester cannot decide their own request and is removed from the
  approver snapshot of every step.
- Permissions: create requires `query:write`; list/detail requires
  `approval:read`; approve/reject/issue-token require `approval:act`; template
  writes require `policy:publish`.
- Every request, step decision, and token issuance is audited; the HTTP audit
  middleware records the mutating calls.
- The security settings page shows "My requests" and "Pending approval", the
  step progress of each request, approve/reject actions with a comment, a
  one-time token display for the requester, and the template list.

## Steps and templates

An approval walks a template's steps in order:

```json
{
  "steps": [
    { "mode": "any", "roles": ["dba"], "users": [] },
    { "mode": "all", "roles": ["security_admin"], "users": ["alice"] }
  ]
}
```

- `any` completes with one approval from any approver listed for the step.
- `all` is a countersign: every user resolved for the step must approve.
  A user may vote once per step; a duplicate vote is refused.
- Roles and users are resolved to a concrete user snapshot when the request is
  created, and only users in that snapshot may vote. Later role edits do not
  widen or deadlock an in-flight approval; the declared roles/users are kept for
  display and audit. A request that resolves to no approver other than the
  requester is rejected with `APPROVAL_STEP_NO_APPROVER`.
- An empty approver list is the built-in single-step default: any holder of
  `approval:act`.
- A rejection on any step rejects the request and marks the remaining steps
  `skipped`. The request only becomes `approved` after the last step completes.
- An approved request also satisfies the resource scope: a role that holds
  `query:write` but not `query:ddl` may execute the approved statements. Rules
  (including `block`) are re-evaluated at execution time.
- The request stores the authoritative ordered statement list. Execution
  always runs that stored list; a client cannot substitute different SQL.
- Templates are unique per scope. Resolution prefers a connection template over
  a global one; `POST /api/approvals` accepts `template_id` to override it.
- Template documents are validated when published: at least one step, at most
  10 steps, no empty step, no blank approver. Publishing a template for a scope
  replaces the previous one.
- Step transitions happen in one SQLite `IMMEDIATE` transaction; the request
  state and the vote are written together, so a crash cannot leave a vote
  without its state change.

## Execution

The execution model follows Alibaba Cloud DMS: the approved ticket owns the
SQL, and an execution mode decides who triggers it.

| Mode | Trigger | DMS name |
|---|---|---|
| `submitter` (default) | the requester calls `POST /api/approvals/{id}/execute` | COMMITOR |
| `last_approver` | the approver who completes the last step triggers execution | LAST_AUDITOR |
| `auto` | the server executes immediately after the last approval | AUTO |

- The mode is chosen when the request is created (`execution_mode`), or defaults
  to `DBX_APPROVAL_EXECUTION_MODE` (unset or invalid means `submitter`).
- `last_approver` and `auto` run without the requester's session, so they are
  rejected at creation unless the connection has `save_password=true`. The
  expected degraded mode for session-only credentials is `submitter`.
- Execution re-binds the stored statements: statement digest, connection
  configuration hash, database, schema, current policy bundle hash, and the
  current require-approval rule IDs must match the request hash. A mismatch
  fails the request with `APPROVAL_BINDING_MISMATCH`; a `block` rule fails it
  with `POLICY_DENIED`.
- `claim_approval_execution` moves `approved -> executing` atomically, so one
  approval executes at most once. The outcome is `executed` or
  `execution_failed` with `execution_error` and `executed_by`.
- Execution events are audited with `source=approval` and the approval ID; SQL
  events carry the same execution ID.
- The one-time token endpoint remains for CLI/MCP/external clients. It binds the
  same request hash and is consumed before execution, independently of the
  server-side one-shot claim.

## API

`POST /api/approvals`, `GET /api/approvals`, `GET /api/approvals/{id}`,
`POST /api/approvals/{id}/approve`, `POST /api/approvals/{id}/reject`,
`POST /api/approvals/{id}/execute`, `POST /api/approvals/{id}/execute-token`,
`GET/POST /api/approval-templates`, `PUT/DELETE /api/approval-templates/{id}`.

`POST /api/approvals/{id}/execute` requires `query:write`, the requester's
identity, `approved` status, and `submitter` mode. It returns the refreshed
request with the execution status.

`GET /api/approvals/{id}` returns the request, its steps, and the recorded
votes. It is limited to the requester, an administrator, and actors who may
decide one of the steps.

## Data model

`approval_requests` (including `statements_json`, `execution_mode`,
`execution_error`, `executed_by`), `approval_steps`, `approval_step_decisions`,
`approval_templates`, `approval_tokens` (append-style; tokens are never reused).

## Non-goals

- Email notifications. The generic webhook, DingTalk, and Feishu/Lark bots are
  supported; mail delivery is expected through an SMTP bridge in front of the
  webhook rather than a built-in SMTP client.
- A durable notification outbox; delivery is best-effort from the request path.
- SLA reminders/escalation, scheduled execution, and break-glass overrides.
- Structured template editing UI; the settings page edits the steps JSON.
- Tokens are accepted on the single-statement path, script/batch execution, and
  explicit `use_transaction` batches (`X-DBX-Approval-Token` with a request
  created from the full `statements` list). Manual transactions still treat
  `require_approval` as a hard stop.
