---
paths:
  - 'database/migrations/**'
---

# Migrations

## Ciphertext columns are base64 in text, and grant_payload must stay text-preserving
Every `_ct` column, public key and signature is base64 in a `text` column, not BYTEA/BLOB: Postgres returns BYTEA as a stream resource while SQLite returns a string, and that only bites in production. `App\Support\Ciphertext` is the only thing that knows the encoding.

`vault_memberships.grant_payload` is declared `json`, which on Postgres preserves the input text verbatim. Never migrate it to `jsonb` — jsonb reorders keys and normalises whitespace, which would invalidate every stored Ed25519 grant signature. `text` is the honest type if it is ever revisited.

## Columns holding signed bytes are json or text — never jsonb
`vault_memberships.grant_payload` (`json`), `audit_events.metadata` (`text`) and `user_identity_archive.rotation_payload` (`text`) hold bytes somebody signed. The database must have no opinion about them.

Measured on Postgres 17 with one deliberately awkward string: `jsonb` reordered the keys, normalised whitespace, unescaped `\/`, and dropped a duplicate key keeping the LAST value — `viewer` where the signed bytes said `editor`. Any of the first three makes the signature fail to verify in a way indistinguishable from tampering, on a row written correctly. The fourth changes what the document says.

Invisible on SQLite, where a column type is close to a comment, so this cannot be caught by the default suite. `tests/Feature/PostgresStorageTest.php` asserts the round trip (not just `data_type`) and runs in the CI Postgres job. Its fixture is deliberately non-canonical — a canonical string survives jsonb by luck.

If the type is ever revisited, `text` is the honest choice: a signed blob that happens to look like JSON is not a document.
