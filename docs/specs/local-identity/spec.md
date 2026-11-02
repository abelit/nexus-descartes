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
- Role bindings carry `global`, `connection`, or `connection_group` scope
  (`database` is rejected until enforcement exists). Child groups inherit a
  parent binding at authorization time via a recursive query.
- Execution authorization: a local user with bindings may only touch covered
  connections and must hold `query:read` / `query:write` / `query:ddl` for the
  statement. Users without bindings keep role-only behavior. This check runs in
  every governance mode (it is authorization, not observation).

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
| `GET` | `/api/roles` | `admin:users` |

## Non-goals

- hilbert JWT login (blocked on independent keys and `aud=dbx`).
- Route-permission matrix for every API prefix; audit and user administration
  are gated first, query/connection gating follows with the policy engine.
