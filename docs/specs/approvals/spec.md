# Approval requests and execution tokens

Issue: enterprise audit / access governance, Phase D (first slice). Tracking
plan: `.claude/plans/dms-dbx-mutable-bear.md`.

## Scope and acceptance

- A request is created only for a statement the built-in rules mark
  `require_approval`; otherwise creation fails with `APPROVAL_NOT_REQUIRED`.
- The request is bound to a deterministic hash over: connection ID, connection
  configuration hash, database, schema, ordered-statement digest, policy bundle
  hash, and the sorted rule IDs that required approval.
- One-time execution tokens store only a SHA-256 hash, carry the requester and
  the request hash, expire after 5 minutes, and are consumed atomically.
- A decision can be made once: approving or rejecting a non-pending request
  fails, and the requester cannot decide their own request.
- Permissions: create requires `query:write`; list requires `approval:read`;
  approve/reject/issue-token require `approval:act`.
- Every request and decision is visible through `GET /api/approvals`; the HTTP
  audit middleware records the mutating calls.
- The security settings page shows "My requests" and "Pending approval", with
  approve/reject actions and a one-time token display for the requester.

## API

`POST /api/approvals`, `GET /api/approvals`, `POST /api/approvals/{id}/approve`,
`POST /api/approvals/{id}/reject`, `POST /api/approvals/{id}/execute-token`.

## Data model

`approval_requests`, `approval_tokens` (append-style; tokens are never reused).

## Non-goals

- Multi-step / countersigned approval templates and notifications.
- Approval tokens are accepted on the single-statement path
  (`X-DBX-Approval-Token`); batch and manual-transaction paths treat
  `require_approval` as a hard stop until per-batch binding exists.
