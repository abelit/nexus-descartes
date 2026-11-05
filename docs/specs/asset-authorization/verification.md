# Asset authorization verification

## Automated

```bash
cargo test -p dbx-core --features enterprise-audit --lib governance::assets
cargo test -p dbx-core --features enterprise-audit --lib identity
cargo test -p dbx-core --features enterprise-audit --lib approval
cargo check -p dbx-web --features enterprise-audit --bin dbx-web --tests
pnpm typecheck
pnpm vitest run src/components/settings/__tests__/settingsSearchCoverage.spec.ts
```

The resolver tests cover table/schema/database coverage, permission
implication (`query:write` implies read), global roles, table patterns, and
risk-based statement denial (including fail-closed unproven SQL). The identity
tests cover scoped permission resolution, expiry, and session revocation; a
dedicated migration-idempotence test is still pending.

`cargo test -p dbx-web --bin dbx-web users::tests` covers the grant ceiling
(role assignment, asset coverage, custom-role permissions, approval-only roles)
and the `expires_at: null` vs absent semantics for `PATCH`.

## Manual acceptance

1. As `admin`, create `viewer@example.com` with an asset grant: table
   `orders` in `app.public`.
2. Sign in as the viewer:
   - the sidebar lists only the granted connection and its parent
     database/schema;
   - `SELECT * FROM orders` succeeds;
   - `SELECT * FROM secrets` fails with `ASSET_ACCESS_DENIED`;
   - `INSERT`, `DROP`, export, import, transfer, SQL file, and Mongo access to
     any other collection are denied;
   - the connection list contains a credential reference, not the password.
3. Add a second grant for `reports` in `app.public` and confirm the viewer sees
   both tables without re-login (the grant change revokes the old session, so a
   fresh login or the next request with a reissued session is required).
4. Remove the `orders` grant and confirm the next query is denied and the
   connection disappears from the list once the schema metadata is refreshed.
5. As an `operator`, run a DDL statement on a granted database:
   `APPROVAL_REQUIRED` under an approval rule; approve as a DBA, then execute
   the ticket. The execution is audited with `source=approval` and the
   requester as actor.
6. Revoke the requester's grant after approval; executing the ticket now fails
   with `ASSET_ACCESS_DENIED`.
7. Ceiling: sign in as a `security_admin`. Creating an `admin` user, assigning
   the `admin` role, creating a custom role with `admin:settings`, granting
   `dba` on an asset, and resetting a DBA's password must all return 403
   (`GRANT_CEILING` / `USER_MANAGEMENT_CEILING`). Resetting an auditor's
   password and assigning `auditor` remain allowed.
8. Access UI: open **Edit access** for a user, verify the cascade loads live
   databases/schemas/tables, add a table pattern, edit the expiry, delete with
   confirmation, and run **Check effective access**. The grant must appear in
   **Access inventory** and be filterable by connection, role, status, and
   table.
9. Inventory: remove a connection and confirm its grants show `stale`; expire a
   grant and confirm it is marked expired rather than silently disappearing.

## Access groups (manual acceptance)

1. Create an access group and add an **asset-only** user (a user whose global
   role was cleared). Add a `viewer` grant on one connection.
2. Sign in as that member: `/api/connection/list` contains only the granted
   connection; `SELECT` on its tables succeeds; writes fail with
   `ASSET_SCOPE_UNPROVEN`; a different connection fails with
   `ASSET_ACCESS_DENIED`.
3. `GET /api/users/{id}/effective-access` reports the group's role under
   `asset_roles` and marks the permission source as `grant`; navigation flags
   are true for the granted connection.
4. `GET /api/users/{id}/bindings` includes the inherited grant
   (`principal_type=group`); the UI shows it read-only with a Group badge.
5. `GET /api/asset-grants` shows the group name and member count; filtering by
   the member's id returns the group grant.
6. Removing the member or deleting the group revokes access and sessions.
   Duplicate group names return 409, blank names 400, and deleting a group
   removes its grants and memberships in the same transaction.
7. Confirm `asset_group` lifecycle events and `asset_grant` events are present
   in the audit log.

## Self-service access requests (manual acceptance)

1. Sign in as a user with no roles and no grants. Open the user menu →
   **Request database access**; the options endpoint must list requestable roles
   and connection names, and the form must allow manual database/schema/table
   entry even when metadata calls are denied.
2. Submit a 1-hour `viewer` request for a connection. Confirm
   `GET /api/access-requests?scope=mine` returns it as `pending`, and a second
   identical submission returns 409 `ACCESS_REQUEST_EXISTS`.
3. As an administrator, open Users & roles → **Access requests**, approve with a
   note. Confirm the request becomes `approved` with `grant_id`, the requester
   gains a normal user grant expiring at the requested window end, and the
   requester can query the connection.
4. Confirm an administrator cannot decide their own request
   (`ACCESS_REQUEST_SELF_APPROVAL`), and a `security_admin` without the data
   permissions is refused by the grant ceiling.
5. Reject or cancel another request: no grant is created and the status is
   terminal. Approving an already-decided request returns
   `ACCESS_REQUEST_ALREADY_DECIDED`.
6. Verify `access_request` created/approved/rejected/cancelled audit events and
   an `asset_grant` created event for the approval.

## Data policies (manual acceptance)

1. Sign in as an administrator, open Users & roles → **Data policies**, create a
   `mask` policy for a test table's text column (for example `name`) and a
   `row_filter` policy whose allowed values are a subset of its id column.
2. Run `SELECT * FROM <table>` as a non-administrator: masked values are
   replaced, and only allowed rows are returned.
3. Run `SELECT <masked column> AS alias` and confirm
   `COLUMN_MASK_UNPROVEN`; run `SELECT COUNT(*)` and confirm
   `ROW_POLICY_UNPROVEN`.
4. Run the same queries as an administrator and confirm values/rows are not
   filtered (administrators bypass data policies).
5. Disable/delete the policies and confirm the next query is unmasked.
6. Policy rules: add a rule with `tables: ["<table>"]`, publish, and use
   `POST /api/governance/simulate` (or execute as a non-admin) to confirm the
   rule matches only statements that reference that table. Unparseable SQL does
   not match a table-scoped rule.

## Task center, unmask grants and role management (manual acceptance)

1. As a user without `approval:read`, call `GET /api/my-tasks`: it returns the
   user's own SQL approvals and access requests. `GET /api/approvals?mine=true`
   still returns 403, and another user's rows never appear.
2. Submit an access request, approve it as an administrator, and confirm the
   task center shows the terminal state/toast and opens the requester dialog.
3. With a mask policy active, `SELECT * FROM <table>` is masked and
   `POST /api/query/execute-multi` with `maxResultBytes` (the table-data path)
   is masked too.
4. Request the `unmasker` role for that table through access requests, approve
   it, and confirm values are unmasked while the row filter still limits rows.
   Delete the grant and confirm masking returns; the grant expiry is the
   requested access window.
5. Create a custom role in Users & roles (the New role form must open), assign
   it to a user, and confirm the effective permissions.
6. Edit a non-admin built-in role, confirm the override is listed and takes
   effect; reset it via `DELETE /api/roles/{code}`. Editing the `admin` role
   returns 403 `ADMIN_ROLE_IMMUTABLE`.

## Docker E2E (pending)

The dedicated `scripts/e2e-asset-authz.sh` from the plan is not implemented
yet. Until it lands, run the manual acceptance above against the Docker
acceptance stack and use `scripts/e2e-governance.sh` for the approval and audit
regression. The pending script must cover connection/database/schema/table
visibility, SELECT allowed while write/DDL are denied, export/import/transfer/
SQL-file/Mongo denial, password redaction, approval execution after grant
revocation, and legacy binding migration after a restart.
