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
implication (`query:write` implies read), global roles, and table patterns.
The identity tests cover migration idempotence, legacy equivalence, expiry,
session revocation, and scoped permission resolution.

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

## Docker E2E (pending)

The dedicated `scripts/e2e-asset-authz.sh` from the plan is not implemented
yet. Until it lands, run the manual acceptance above against the Docker
acceptance stack and use `scripts/e2e-governance.sh` for the approval and audit
regression. The pending script must cover connection/database/schema/table
visibility, SELECT allowed while write/DDL are denied, export/import/transfer/
SQL-file/Mongo denial, password redaction, approval execution after grant
revocation, and legacy binding migration after a restart.
