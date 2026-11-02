# Versioned policy documents: verification

## Automated

```bash
RUST_MIN_STACK=8388608 cargo test -p dbx-core --features enterprise-audit --lib governance
RUST_MIN_STACK=8388608 cargo test -p dbx-core --features enterprise-audit --lib persistence::storage::policy
cargo check -p dbx-web --features enterprise-audit --bin dbx-web
```

Covered:

- an empty set compiles to exactly the built-ins and a stable bundle hash;
- a published connection-scoped rule tightens that connection only and changes
  the bundle hash;
- a stored rule reusing a built-in id replaces it, including `enabled: false`
  disabling `global.ddl.warn`;
- invalid documents (unparsable JSON, empty message) are rejected;
- the narrower scope wins when two scopes define the same rule id;
- scoped and database-glob matching; a database scope that names both the
  connection and the database (`<connection_id>::<database>`) matches only that
  pair; disabled rules do not fire;
- storage: versions are monotonic per scope, the latest is returned per scope,
  and rollback appends a new version.

## Manual

1. Publish a connection-scoped `block` for DML; simulate a bounded UPDATE on
   that connection → `block` with the new rule id; on another connection →
   allow.
2. Note the `policy_bundle_hash` from simulate; publish another version and
   simulate again → hash changed.
3. Create an approval, then publish a policy that changes the rule set; the
   issued token now fails with `APPROVAL_TOKEN_BINDING_MISMATCH`.
4. Roll back to the previous version → the decision returns to the earlier
   behavior and a new version number is listed.

## Known gaps

- The compiled policy is process-wide; a multi-instance deployment needs a
  shared store and a cache invalidation channel.
- No rule-review UI yet; publishing is done through the API.
- Connection-group scopes wait for server-owned connection groups.
