# Local identity: verification

## Automated

```bash
cargo test -p dbx-core --features enterprise-audit --lib identity
cargo check -p dbx-web --features enterprise-audit --bin dbx-web
cargo check -p dbx-web --features enterprise-audit --tests
```

The identity suite covers:

- `admin` holds every permission; `viewer` is read-only; `auditor` exports but
  cannot execute; unknown roles grant nothing;
- permission unions are deduplicated and sorted; codes round-trip through
  `parse`;
- passwords hash and verify, and a malformed hash never verifies;
- session tokens are stored as 64-character hex digests;
- idle and absolute limits both expire a session;
- the built-in admin is created once, bound to `admin`, and keeps its password;
- built-in roles and their permission rows are seeded;
- an expired role binding does not grant its role;
- custom roles round-trip with their permissions, cannot reuse a built-in code,
  cannot be edited/deleted when built-in, and cannot be deleted while bound;
- a group-scoped grant covers the group's connections and descendant groups
  but not unrelated connections; database/schema/table grants match only their
  target and broader grants cover narrower objects; a table grant never covers
  a database-wide operation;
- legacy non-global bindings migrate into `asset_grants` idempotently and their
  old rows are removed, so deleting a grant cannot be undone by a stale row;
- table-name patterns match within the granted scope; global roles cover all
  objects; zero-grant users are denied; category/connection visibility keeps
  parent nodes for a granted table but not unrelated databases/schemas;
- a session row can be stored, found, listed, revoked, and expired rows are
  purged;
- route classification: SQL execution requires `query:write`, listing requires
  `query:read`, connection writes need `connection:write`, exports/imports and
  administration have their own permissions, and unknown prefixes are
  unclassified.

## Manual

1. Start with `DBX_PASSWORD=test`; log in with no email → `admin` actor with
   `permissions` containing `audit:read`.
2. `POST /api/users` with role `viewer`; log in as that user in a second browser
   profile; `/api/auth/check` shows `query:read` only and `/api/audit/events`
   returns 403.
3. `PATCH /api/users/{id}` status `disabled`; the viewer's next request is
   rejected and their persisted session is revoked.
4. Change the admin password; every other session (including a second admin
   browser) is logged out, and survives a restart as revoked.
5. Restart the process; an admin session still works until the idle limit, and
   an unknown cookie is rejected (no bootstrap fallback).
6. `/api/auth/setup` with `DBX_SETUP_TOKEN` set requires the token; after the
   first user exists it is refused.

## Known gaps

- Login throttling is keyed by client address + account; an attacker rotating
  accounts from one address is slowed, but a distributed attack is not.
- Roles are re-resolved only at login or lazy session restore; a role change
  revokes sessions instead of hot-updating permissions.
- `client_ip` is recorded on audit events and resolved per request, but login
  does not yet store it on the session row (admin session lists show it only for
  sessions created after the next slice).
