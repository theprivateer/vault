---
paths:
  - '.github/workflows/**'
---

# Workflows

## CI runs the suite on Postgres as well, and tests the audit grant in SQL
The `postgres` job is not redundant with `backend`. Production is Postgres and the default suite runs on SQLite, where a column type is close to a comment — so the divergences that matter here (json vs jsonb on signed bytes) are invisible by construction.

It also carries the one check nothing else can make: create an unprivileged role, `REVOKE UPDATE, DELETE ON audit_events`, then prove `INSERT` still succeeds while `UPDATE` and `DELETE` are refused **by the database**. That is the append-only log's third defence, and the only one a future code change cannot undo. The step also asserts the revoke is scoped (`has_table_privilege` on vaults/secrets) — an over-broad grant would leave the app unable to edit a secret, which is the same mistake in the other direction and would be found by a user rather than a test.

Local equivalent: `DB_CONNECTION=pgsql DB_HOST=127.0.0.1 DB_DATABASE=vault_test DB_USERNAME=postgres php artisan test`. The phpunit.xml `<env>` entries do not override real environment variables, so this works without editing anything.
