# Versioned policy documents

Issue: enterprise audit / access governance, Phase C (stored policies).
Tracking plan: `.claude/plans/dms-dbx-mutable-bear.md`.

## Scope and acceptance

- `policy_documents` stores immutable versions per scope
  (`global`, `connection:<id>`, `database:<name>`); publishing appends a new
  version, rollback publishes a copy of an old version.
- Compilation merges the code-defined built-ins with the latest published
  document of every scope. A stored rule with a built-in's id replaces it
  (`enabled: false` disables a built-in).
- Evaluation takes the strictest effect across all applicable scopes
  (`block` > `require_approval` > `warn` > `allow`); a narrower scope can only
  tighten a broader one.
- The compiled set carries `policy_bundle_hash` (engine version + built-ins +
  documents). Decisions, audit-facing metadata, and approval binding use it, so
  publishing a policy invalidates outstanding approvals.
- Publishing validates by compiling the candidate set first; an invalid
  document never becomes effective. The process-wide compiled policy is
  replaced only after a successful publish.
- The compiled policy is loaded at startup; an invalid stored document fails
  startup instead of silently falling back to built-ins.
- `POST /api/governance/simulate` and `GET /api/policies/effective` report the
  bundle hash and every matched rule.
- Reads require `policy:read`; publish/rollback require `policy:publish`.
- The security settings page publishes, lists, and rolls back documents, and
  shows the effective rules and bundle hash.

## Document shape

```json
{ "rules": [ { "id": "...", "enabled": true, "priority": 100,
               "action": "block|warn|require_approval|allow",
               "message": "...",
               "match": { "statement_types": ["ddl"],
                          "production_only": true,
                          "unbounded_only": false,
                          "requires_where": null,
                          "databases": ["prod_*"] } } ] }
```

## Non-goals

- Connection-group scopes (server-owned groups are not implemented yet).
- Per-user/role rule scoping.
- Policy diff UI and approvals for policy changes (publish is audited by the
  generic HTTP middleware).
