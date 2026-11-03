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
- `grants`: unexpired asset grants for the user.
- `group_connections`: recursive membership of connection groups, including
  descendant groups.

`permits(connection, database, schema, table, permission)` returns the matching
grant ids and whether coverage is broad. `authorize_statements` classifies each
statement with `sql_risk` and `sql_analysis`, tracks `USE`, and requires every
referenced object to be covered. `INSERT ... SELECT` needs write on the target
and read on the sources.

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
| `DELETE` | `/api/users/{id}/bindings/{binding_id}` | `admin:users` |

Creating or deleting a grant revokes the target user's sessions, so a grant
change takes effect immediately. Grant changes are audited as `asset_grant`
events.

## Non-goals

- Row-level filtering, column-level authorization or masking, deny rules, and
  "most specific wins".
- Redis key, MQ topic, or Nacos namespace scopes (connection-level only).
- Following renames automatically; the admin must re-grant.
- Desktop, CLI, and local MCP are best-effort; the Web/Docker server is the
  enforcement boundary.
