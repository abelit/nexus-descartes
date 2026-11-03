# Local identity and RBAC

Issue: enterprise audit / access governance, Phase B. Tracking plan:
`.claude/plans/dms-dbx-mutable-bear.md`.

## Scope and acceptance

- Local users with Argon2 password hashes; the legacy shared password is
  migrated into a built-in `admin` user on startup (`DBX_PASSWORD` stays
  authoritative when set).
- Roles are code-defined and seeded into `roles` / `role_permissions`:
  `admin`, `security_admin`, `dba`, `auditor`, `operator`, `viewer`.
- Permission codes cover audit, policy, approval, connection, query, export,
  import, and administration. Unknown roles grant nothing.
- `role_bindings` carry scope and optional expiry; expired bindings do not
  grant a role.
- Sessions are persisted in `web_sessions` with only the token hash stored.
  Idle (default 30 min) and absolute (default 24 h) limits are both enforced.
  Password changes and role changes revoke the user's other sessions, including
  the persisted rows, so a restart cannot revive them.
- An unknown token is never an administrator: the previous bootstrap fallback
  is removed.
- `/api/auth/check` returns roles and effective permission codes.
- The audit API requires `audit:read` / `audit:export` / `audit:verify` from
  the session, with the bootstrap token or loopback as the automation fallback.
- `POST /api/auth/setup` is refused once any local user exists, and requires
  `DBX_SETUP_TOKEN` when that variable is configured.
- User administration (`/api/users`, `/roles`) requires `admin:users`.
- A prefix→permission table classifies API routes. `DBX_GOVERNANCE_MODE=observe`
  (default) serves unclassified routes; `enforce` denies missing permissions and
  requires `admin:settings` for unclassified routes
  (`ROUTE_PERMISSION_UNCLASSIFIED` otherwise), so new routes must be classified
  before regular users can call them.

## Resource scopes

- `connection_groups` / `connection_group_members` are server-owned; the client
  sidebar layout is never an authorization source.
- Global roles stay in `role_bindings` (`scope_type='global'`). Non-global
  targets live in `asset_grants`: `connection_group`, `connection`, `database`,
  `schema`, or `table`, with optional table-name patterns (`*`/`?`) and
  expiry. Legacy connection/database bindings are migrated into this table and
  their old rows are removed in the same transaction.
- A broader grant covers narrower objects; a table grant never covers a
  database-wide operation. Multiple grants are unioned. Child groups inherit a
  parent grant at authorization time via a recursive query.
- Execution authorization: a local user must hold `query:read` /
  `query:write` / `query:ddl` (chosen per statement risk) on every referenced
  object. Statements whose objects cannot be proven require a connection,
  database, or schema grant; table-only grants fail closed with
  `ASSET_SCOPE_UNPROVEN`. This runs in every governance mode.
- Visibility: `/api/connection/list` and `/api/schema/*` return only assets the
  actor can navigate to; exact table metadata is denied outside the grant.
  Saved passwords are redacted for asset-scoped users.
- Users with no global binding and no asset grant are denied. Global roles are
  used for non-data routes (audit, users, policy); asset roles satisfy the
  data-route floors (`connection:read`, `query:*`, `export:data`, `import:data`,
  `approval:read/act`) and are then checked per object. Connection
  configuration writes stay global `connection:write`; an asset-scoped user can
  connect/test only a saved, authorized connection and never retarget its host
  or port.

## Custom roles and user administration

- Custom roles live in `roles`/`role_permissions`; a process-wide registry is
  seeded with built-ins and replaced from the database at startup and after
  every role change.
- A custom role may not reuse a built-in code; built-ins are immutable; a role
  still bound to a user cannot be deleted.
- Editing a role revokes the sessions of every bound user, so permissions never
  go stale inside a session.
- Admins can reset a user's password, edit the display name, list a user's live
  sessions, and revoke one session or all of them.

## Data model

`users`, `roles`, `role_permissions`, `role_bindings`, `web_sessions`.

## API

| Method | Path | Permission |
| --- | --- | --- |
| `GET` | `/api/users` | `admin:users` |
| `POST` | `/api/users` | `admin:users` |
| `PATCH` | `/api/users/{id}` | `admin:users` |
| `POST` | `/api/users/{id}/sessions/revoke` | `admin:users` |
| `GET`/`POST` | `/api/users/{id}/bindings` | `admin:users` |
| `DELETE` | `/api/users/{id}/bindings/{binding_id}` | `admin:users` |
| `GET` | `/api/roles` | `admin:users` |

## Non-goals

- hilbert JWT login (blocked on independent keys and `aud=dbx`).
- Route-permission matrix for every API prefix; audit and user administration
  are gated first, query/connection gating follows with the policy engine.
