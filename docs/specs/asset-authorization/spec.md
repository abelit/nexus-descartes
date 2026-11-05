# Asset authorization

Issue: enterprise access governance, asset-level grants. Tracking plan:
`.claude/plans/dms-dbx-mutable-bear.md`.

## Scope and acceptance

- Asset grants answer "which connections, databases, schemas, and tables may
  this local user touch, and with which role?" They are enforced on the server;
  the sidebar and metadata filters are UX only.
- Targets: `connection_group`, `connection`, `database`, `schema`, `table`.
  Table names optionally use `*` / `?` patterns. Every target can carry an
  expiry and a reason.
- Grants are allow-only and unioned. A broader grant covers narrower objects;
  a table grant never covers a database-wide operation.
- Global roles stay in `role_bindings` (`scope_type='global'`). Non-global
  targets live in `asset_grants`; legacy non-global bindings are migrated once
  and removed in the same transaction.
- A user with no global role and no asset grant can sign in but cannot read
  connections, metadata, or execute SQL.
- Execution authorization needs the risk-appropriate permission on every
  referenced object: `query:read` for reads, `query:write` for DML, `query:ddl`
  for DDL. A one-time approval allows `query:write` to stand in for `query:ddl`
  on the approved statements only.
- Statements whose object references cannot be parsed or proven (`CALL`,
  dynamic SQL, unsupported dialect, table-only grants) fail closed with
  `ASSET_SCOPE_UNPROVEN`. A connection/database/schema grant is the escape
  hatch.
- Visibility: `/api/connection/list`, `/api/schema/databases|schemas|tables`,
  object lists, table metadata, and schema-cache reads return only authorized
  objects. Exact table metadata is denied outside the grant.
- Saved passwords are redacted for asset-scoped users. They connect and query
  through the server-held configuration; client-supplied host/port is ignored
  for managed users.
- Connection configuration writes (`save`, `remove`, `mcp/add`, `mcp/remove`,
  `mcp/duplicate`) remain global-`connection:write` operations: a scoped role
  cannot retarget or add a connection. `connect` and `test` accept
  `connection:read` for a saved, authorized connection.

## Authorization model

`AssetScopeSnapshot` is loaded once per request or statement batch:

- `global_roles`: unexpired global bindings.
- `grants`: unexpired direct user grants plus grants inherited from every access
  group the user belongs to. A group is a named user set in the asset layer; it
  never adds a global role.
- `group_connections`: recursive membership of connection groups, including
  descendant groups.

`permits(connection, database, schema, table, permission)` returns the matching
grant ids and whether coverage is broad. `authorize_statements` classifies each
statement with `sql_risk` and `sql_analysis` and requires every referenced
object to be covered by the statement's risk permission. This is conservative:
`INSERT ... SELECT` needs write on both the target and its sources. Scripts that
may switch databases (`USE`) require a connection-level grant before a SQL file
runs, and each statement is then re-checked by risk.

### Access groups

`asset_groups` + `asset_group_members` let an administrator attach one grant to
a team instead of every user. A grant's `principal_type` is `user` or `group`;
resolution unions both for the signed-in user. Membership grants no global role,
so a group member is still an asset-only user unless separately bound.

Group deletions cascade grants and memberships in one transaction. Adding or
removing a member, and adding/updating/deleting a group grant, revokes the
affected members' sessions; the next request resolves the new effective grants.
All group mutations require `admin:users`, pass the same grant ceiling, and are
audited (`asset_group` lifecycle, `asset_grant` changes).

### Self-service access requests

Any signed-in user may request a time-bound personal grant, including a user
with no roles or grants at all. A request stores the role, target, duration
(1 hour to 30 days), requested window end, and justification. Pending requests
for the same requester/role/target are deduplicated with
`ACCESS_REQUEST_EXISTS`.

`admin:users` holders approve or reject. The request view exposes
`approver_names` for pending requests: active `admin:users` holders (excluding
the requester) whose own snapshot covers every permission of the requested role
at the target, so the UI can show who can actually decide it; decided requests
carry `decided_by_name`. Self-decisions are refused
(`ACCESS_REQUEST_SELF_APPROVAL`); the approving actor must pass the same grant
ceiling as a manual grant, and an expired window returns
`ACCESS_REQUEST_EXPIRED`. Approval inserts a normal user grant with the
requested expiry and links it to the request (`grant_id`); the requester's
sessions are revoked. Rejection and cancellation never create a grant. The
request row remains as history after the grant expires; `expired` is derived
from `expires_at`.

The `/api/access-requests*` routes are intentionally outside the route-permission
table: any signed-in actor can list/create/cancel their own requests. Handlers
check ownership and require `admin:users` for the all-requests view and
approve/reject.

### Grant ceiling

`admin:users` alone does not make an administrator all-powerful. Every
assignment is checked against the permissions the actor already holds:

- a **global role** can only be assigned when the actor holds every permission
  in it globally;
- an **asset grant** can only be created or edited when the actor's own
  snapshot covers every data permission it would grant at that exact target;
- a **custom role** can only be created or updated with permissions the actor
  already holds;
- resetting a password requires the actor to hold, globally, every permission
  the target user can exercise (including asset-scoped roles). This closes the
  impersonation path where a security administrator resets a DBA's password and
  signs in as that user.

`GRANT_CEILING` and `USER_MANAGEMENT_CEILING` are returned as 403 responses.
Status changes may not disable the built-in administrator; only administrators
whose permissions cover a privileged target may disable it.

Approval-only roles (`security_admin`, `auditor`) cannot be used for asset
grants: approval visibility is anchored on `connection:read`, so such a grant
would not reach an asset. Custom roles that include `connection:read` plus
approval permissions are allowed.

## Data paths

| Path | Enforcement |
| --- | --- |
| single statement, batch, script, transaction, 2PC, BLOB, manual transaction | `authorize_connection_scope` before the driver; explicit audit context |
| SQL file import | connection-level `query:write` pre-check (scripts can `USE`), then per-statement risk in the spawned executor with a carried audit context |
| table export | exact table `query:read`, plus the route's `export:data` floor |
| table import | target `query:write`, or schema-level `query:ddl` when creating the table |
| whole-database export/dump | database or connection `query:read` |
| transfer | source `query:read` and target `query:write` per table, or broad coverage for all-tables and structure changes; target structure needs `query:ddl` |
| MongoDB CRUD | per-collection `query:read/write/ddl`; database operations need broad coverage |
| MongoDB import/export/dump/restore | per-collection or whole-database coverage as above |
| AI Agent | the request audit context is re-scoped around the agent runtime, so every tool SQL call is authorized as the signed-in user |
| connection management | saved-config connect/test only for authorized connections; configuration writes stay global |
| approvals | creation and execution re-check the requester's current grants; list/detail hide connections outside the actor's grants |
| native jobs, Oracle routines/types | database/schema-level checks; native-job mutation requires a global `query:ddl` role |
| schema cache | key parsed to connection/database/schema/table and checked; unmapped keys are denied for managed users |

## API

| Method | Path | Permission |
| --- | --- | --- |
| `GET` | `/api/users/{id}/bindings` | `admin:users` |
| `POST` | `/api/users/{id}/bindings` | `admin:users` |
| `PATCH` | `/api/users/{id}/bindings/{binding_id}` | `admin:users` |
| `DELETE` | `/api/users/{id}/bindings/{binding_id}` | `admin:users` |
| `GET` | `/api/users/{id}/effective-access?connection_id=…` | `admin:users` |
| `GET` | `/api/asset-grants?user_id=…&connection_id=…&database=…&schema=…&table=…&role_code=…&stale=…` | `admin:users` |
| `GET`/`POST` | `/api/asset-groups` | `admin:users` |
| `GET`/`PATCH`/`DELETE` | `/api/asset-groups/{group_id}` | `admin:users` |
| `POST` | `/api/asset-groups/{group_id}/members` | `admin:users` |
| `DELETE` | `/api/asset-groups/{group_id}/members/{user_id}` | `admin:users` |
| `POST` | `/api/asset-groups/{group_id}/bindings` | `admin:users` |
| `PATCH`/`DELETE` | `/api/asset-groups/{group_id}/bindings/{binding_id}` | `admin:users` |
| `GET` | `/api/access-requests/options` | any signed-in actor |
| `GET`/`POST` | `/api/access-requests` | own requests: any actor; `scope=all`: `admin:users` |
| `POST` | `/api/access-requests/{id}/cancel` | requester |
| `POST` | `/api/access-requests/{id}/approve` | `admin:users` |
| `POST` | `/api/access-requests/{id}/reject` | `admin:users` |
| `GET` | `/api/my-tasks` | any signed-in actor (self-scoped) |
| `GET`/`POST` | `/api/data-policies` | `admin:users` |
| `PATCH`/`DELETE` | `/api/data-policies/{id}` | `admin:users` |

`PATCH` changes the role, expiry, or reason without recreating the grant. An
absent `expires_at` leaves the expiry unchanged; `null` clears it. `effective-access`
returns every permission, the matching grant ids, broad/narrow coverage, and
navigation visibility for a concrete target. `asset-grants` is the administrative
inventory; its response is self-contained (user, role, target labels, connection
and group names, expired/stale flags), and the `stale` filter returns grants
whose connection, group, user, or role no longer exists or whose role has no
grantable data permissions.

`PATCH /api/users/{id}` accepts `role`, `scope`, `status`, `display_name`, and
`clear_global_role`. A role edit always creates a real global binding, even for
an asset-only user; it never reuses one of the user's asset grants as the scope.
`clear_global_role: true` removes every global role while keeping asset grants,
which is how an account is downgraded to asset-only access. It cannot be
combined with `role` or `scope` and is rejected for the built-in administrator.

Creating, updating, or deleting a grant revokes the target user's sessions, so a
grant change takes effect immediately. Grant changes are audited as `asset_grant`
events.

## Administration UI

The governance workspace keeps users and access management together:

- **Users** — create accounts with a global role, change global roles within the
  ceiling, reset passwords where permitted, disable/enable, and revoke sessions.
- **Edit access** — a per-user drawer with global role, asset grants, cascade
  selectors (connection → database → schema → table) backed by live metadata,
  manual entry fallback, table patterns with a match preview, expiry presets,
  inline edit, delete confirmation, an effective-access checker for the selected
  target, and session management.
- **Access inventory** — all grants across users and access groups, filterable
  by user text, connection, role, status, database, schema, and table; expired
  and stale grants are highlighted, user grants open in the per-user drawer,
  group grants open the access group.
- **Access groups** — create/rename/delete groups, add/remove members, and grant
  connections, connection groups, databases, schemas, or tables to the whole
  group with the same cascade selectors and expiry controls.
- **Access requests** — every signed-in user can open *Request database access*
  from the user menu, pick a role/target/duration and track or cancel their own
  requests. Administrators get an **Access requests** tab under Users & roles to
  approve or reject with a note.
- **Data policies** — administrators create column masks and read row filters
  per connection/database/schema/table/column, enable or disable them, and edit
  or delete them. Policy rules gain a **Tables** matcher in the rule form.
- **Task progress** — every signed-in user sees *My SQL approvals* and *My
  access requests* (backed by `/api/my-tasks`, no `approval:read` required),
  with active counts, terminal toasts and deep links. Access requests open the
  requester dialog; administrators additionally keep the approver inbox/badge.
- **Unmask requests** — the current-user menu offers *Request unmasked data
  view*, preselecting the `unmasker` role in the access-request dialog.

## Data policies (column masks and read row filters)

`data_policies` rows attach to a connection and optionally narrow by database,
schema, table (`*`/`?` patterns), and column (patterns). Two kinds:

- **mask** — replaces a matching result column's values with a full replacement
  (`***`), a partial form (first/last two characters), or an email-style form
  (`a***@example.com`). Nulls stay null; deferred large-value locators for a
  masked column are dropped so the value cannot be re-read in full.
- **row_filter** — keeps result rows whose configured column value is in the
  allow-list. The discriminator column must be present in the result.

Policies are applied centrally in `execute_sql_statement_with_options_typed`
after the driver returns a read-only result, before audit success serialization,
response, or export. Enforcement is fail-closed:

- an aliased masked column (`SELECT email AS e`) is refused with
  `COLUMN_MASK_UNPROVEN` because the alias mapping cannot be proven;
- a row filter whose column is absent (for example `SELECT COUNT(*)`) is
  refused with `ROW_POLICY_UNPROVEN`;
- SQL that cannot be parsed while policies apply is refused with
  `DATA_POLICY_UNPROVEN`.

Administrators (`admin:settings`) and system actors bypass data policies.
There is also an explicit `unmask:data` permission: a global role holding it
(for example the built-in **Unmask data viewer** / `unmasker`) or an asset grant
of that role at the target bypasses column masks, while row filters still apply.
Because the built-in role contains only `unmask:data`, it is requestable through
the existing time-bound access-request flow: a user requests the `unmasker` role
for a table/connection, an administrator approves, and the resulting personal
grant expires with the requested window. The user menu exposes
**Request unmasked data view** for this flow. DBAs and other managed users
without `unmask:data` remain masked. Row filters are read filters: writes remain
governed by policy rules, approvals, and asset grants. The administration API is
`GET/POST /api/data-policies` and `PATCH/DELETE /api/data-policies/{id}`
(`admin:users`), with an **Data policies** tab under Users & roles; changes are
audited as `data_policy` events.

## Non-goals

- Column-level authorization beyond masking (granting only a subset of columns),
  deny rules, and "most specific wins".
- Row filters on writes; row-filter predicates other than an allow-list.
- Redis key, MQ topic, or Nacos namespace scopes (connection-level only).
- Following renames automatically; the admin must re-grant.
- Desktop, CLI, and local MCP are best-effort; the Web/Docker server is the
  enforcement boundary.
