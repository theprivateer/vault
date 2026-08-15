---
paths:
  - 'database/migrations/**'
---

# Migrations

## Ciphertext columns are base64 in text, and grant_payload must stay text-preserving
Every `_ct` column, public key and signature is base64 in a `text` column, not BYTEA/BLOB: Postgres returns BYTEA as a stream resource while SQLite returns a string, and that only bites in production. `App\Support\Ciphertext` is the only thing that knows the encoding.

`vault_memberships.grant_payload` is declared `json`, which on Postgres preserves the input text verbatim. Never migrate it to `jsonb` — jsonb reorders keys and normalises whitespace, which would invalidate every stored Ed25519 grant signature. `text` is the honest type if it is ever revisited.
