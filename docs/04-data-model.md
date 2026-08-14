# 04 — Data Model

Conventions throughout:

- **`_ct` suffix = ciphertext.** An opaque envelope ([03](03-cryptographic-design.md#envelope-format)).
  The server validates length and never parses the contents.
- **UUIDv7 public identifiers**, generated client-side so AAD can bind to them before insert.
  Auto-increment `id` stays internal and never appears in a URL or an API response.
- **Every table gets a leakage note.** If a column is plaintext, the reason is written down.
- Postgres in production (`BYTEA`, real `CHECK` constraints, `jsonb`); SQLite is fine for local
  dev and tests, which is the current `.env` default.

## Diagram

```
users ──1:N── user_key_wraps          (password / recovery / [prf] wrappings of the User Key)
  │
  ├──1:1──── user_identities          (X25519 + Ed25519 public keys, encrypted private keys)
  ├──1:1──── user_pin_stores          (encrypted TOFU fingerprint cache)
  ├──1:1──── user_totp                (server-side second factor — unrelated to stored TOTP seeds)
  │
  └──1:N── vault_memberships ──N:1── vaults
                                       │
                                       └──1:N── lockboxes
                                                  ├──1:N── secrets ──1:N── secret_versions
                                                  └──1:N── files

audit_events   (hash-chained, standalone)
share_links    (one-time, standalone)
```

## Tables

### `users`

| Column | Type | Notes |
| --- | --- | --- |
| `id` | bigint PK | internal only |
| `uuid` | uuid unique | UUIDv7, public identifier |
| `email` | string unique | plaintext — needed for login and invites |
| `display_name` | string | plaintext — shown to people you share with |
| `handle` | string unique | plaintext — the share-with identifier |
| `kdf_salt` | binary(16) | not secret; must be fetchable pre-auth |
| `kdf_algorithm` | string | `argon2id` |
| `kdf_params` | json | `{m, t, p, version}` — per-user, for upgrades |
| `auth_key_hash` | string | `Argon2id(authKey)` via Laravel's `argon2id` driver. **Slow, deliberately** — `authKey` inherits only the password's entropy |
| `totp_secret_ct` | binary null | second-factor seed, encrypted with `APP_KEY` — server-side by necessity, and *not* user secret data |
| `totp_confirmed_at` | timestamp null | |
| `recovery_used_at` | timestamp null | drives the "issue a fresh kit" prompt |
| `locked_until` | timestamp null | account-level auth throttling |
| `timestamps` | | |

**Leaks:** who has an account, their email and chosen display name, when they joined. Accepted —
D11 is a small trusted group, and email is required for invites to work at all.

**Not present, deliberately:** no `password` column. Nothing on this table can decrypt anything.

### `user_key_wraps`

| Column | Type | Notes |
| --- | --- | --- |
| `id` / `uuid` | | |
| `user_id` | FK cascade | |
| `method` | enum | `password`, `recovery`, `prf` (reserved) |
| `wrapped_user_key` | binary | envelope; AAD context `user.userkey` |
| `salt` | binary(16) null | the recovery salt, for `method=recovery` |
| `label` | string null | e.g. which passkey, once PRF lands |
| `last_used_at` | timestamp null | |

Unique on `(user_id, method)` for `password`; multiple `prf` rows allowed later. A separate table
rather than columns on `users` because the set of unlock methods is open-ended — this is what
makes passkey unlock a data change rather than a migration of the auth flow.

### `user_identities`

| Column | Type | Notes |
| --- | --- | --- |
| `user_id` | FK, unique | |
| `x25519_public_key` | binary(32) | plaintext — it is a public key |
| `ed25519_public_key` | binary(32) | plaintext |
| `x25519_private_key_ct` | binary | AAD context `user.privkey.x25519` |
| `ed25519_private_key_ct` | binary | AAD context `user.privkey.ed25519` |
| `self_signature` | binary(64) | Ed25519 over both public keys |
| `fingerprint` | binary(32) | BLAKE2b — a cache; clients recompute and compare |
| `rotated_at` | timestamp null | |

**Trust note:** the server serves these public keys, so it can lie. The self-signature proves the
two keys were published together, and the client-side pin store plus fingerprint verification
(D8) is what actually detects substitution. The database is not the root of trust here — the
user's out-of-band comparison is.

### `user_pin_stores`

| Column | Type | Notes |
| --- | --- | --- |
| `user_id` | FK, unique | |
| `pins_ct` | binary | `{ [userUuid]: fingerprintHex }`, encrypted under the User Key |
| `version` | int | optimistic concurrency across devices |

Encrypted so the server cannot see, or quietly reset, whose keys you have verified.

### `vaults`

| Column | Type | Notes |
| --- | --- | --- |
| `id` / `uuid` | | client-generated UUIDv7 |
| `owner_id` | FK | plaintext — needed for authorisation |
| `payload_ct` | binary | `{name, description}` |
| `wrapped_item_key` | binary | Item Key wrapped by the Vault Key |
| `payload_version` | smallint | bound into AAD |
| `key_epoch` | int default 1 | increments on rotation |
| `rekey_required_at` | timestamp null | set on revocation; drives the owner's re-key prompt |
| `timestamps`, `deleted_at` | | soft deletes |

**Leaks:** existence, ownership, timestamps, how many vaults a user has. **The name is
encrypted** — the single biggest change from 2017, where `vaults.name` was plaintext.

### `vault_memberships`

Replaces the 2017 `user_vault` pivot with its `read_only` boolean.

| Column | Type | Notes |
| --- | --- | --- |
| `id` / `uuid` | | |
| `vault_id`, `user_id` | FK cascade | unique together |
| `role` | enum | `owner`, `editor`, `viewer` |
| `wrapped_vault_key` | binary | sealed box to the member's X25519 key |
| `key_epoch` | int | must match `vaults.key_epoch` to be usable |
| `granted_by` | FK | |
| `grant_signature` | binary(64) | Ed25519 over the canonical grant |
| `grant_payload` | json | the exact bytes that were signed — stored so signatures stay verifiable if the canonicalisation ever changes |
| `accepted_at` | timestamp null | recipient confirmed the granter's fingerprint |
| `revoked_at` | timestamp null | |

`grant_signature` and `grant_payload` are nullable as built in Phase 3, and become required in
Phase 5 when grants are actually signed. Nullable now so that adding signed grants is a change to
the write path rather than a migration of a populated table.

**Revocation is enforced on read, immediately.** A membership with `revoked_at` set is not a
membership: every query filters it out and every policy treats it as absent, before any re-key has
happened. That part is instant and enforceable; the re-key is neither, and the two are separated
deliberately (see [03 § Revocation](03-cryptographic-design.md#revocation-and-rotation)).

**Leaks:** the sharing graph — who shares what with whom, and when. Named in
[02 § Accepted leakage](02-threat-model.md#accepted-leakage). Hiding it needs private information
retrieval, which is out of scope.

**Enforcement:** `role` is server-enforced for writes. It is not cryptographically enforced for
reads, and cannot be — see [01 § A note on what "read-only" means](01-brief-and-decisions.md#a-note-on-what-read-only-means).

### `lockboxes`

| Column | Type | Notes |
| --- | --- | --- |
| `id` / `uuid` | | |
| `vault_id` | FK cascade | |
| `payload_ct` | binary | `{name, description}` |
| `wrapped_item_key`, `payload_version` | | |
| `sort_order` | int | plaintext — leaks ordering only, and sorting must work while locked |
| `timestamps`, `deleted_at` | | |

The 2017 `control` boolean is gone; that concept was removed by its own migration in 2017 anyway.

### `secrets`

| Column | Type | Notes |
| --- | --- | --- |
| `id` / `uuid` | | |
| `lockbox_id` | FK cascade | |
| `payload_ct` | binary | `{type, key, value, notes, totp?, url?}` — **including the type** |
| `wrapped_item_key`, `payload_version` | | |
| `linked_lockbox_id` | FK null | the 2017 lockbox-as-a-value feature, kept |
| `sort_order` | int | |
| `current_version` | int | mirrors `secret_versions` |
| `timestamps`, `deleted_at` | | |

**The type is inside the payload.** A `type` enum column would tell the server which secrets are
TOTP seeds, which are SSH keys and which are notes — a meaningful targeting signal for free.

**`linked_lockbox_id` is plaintext** because the server enforces that both ends live in the same
vault, which requires seeing the edge. It leaks graph structure, which is already leaked by the
foreign keys.

**The 2017 `paranoid` flag** is dropped as a column and becomes `payload.paranoid` — a client-side
UI hint (require re-auth to reveal, never auto-copy). It was never a security control.

### `secret_versions` (Phase 8)

| Column | Type | Notes |
| --- | --- | --- |
| `secret_id` | FK cascade | |
| `version` | int | unique with `secret_id` |
| `payload_ct`, `wrapped_item_key`, `payload_version` | | each version keeps its own item key |
| `created_by` | FK | |
| `created_at` | timestamp | |

Each version carrying its own Item Key means version history survives Vault Key rotation by
re-wrapping, exactly like a live item, and no version is ever re-encrypted.

**Retention:** unbounded history is a liability — a password you rotated *because it leaked* stays
recoverable forever. Default to keeping the last 20 versions and 180 days, configurable per vault,
with a "purge history" action. This tension is worth a UI note.

### `files`

| Column | Type | Notes |
| --- | --- | --- |
| `id` / `uuid` | | |
| `lockbox_id` | FK cascade | |
| `payload_ct` | binary | `{filename, mime, sha256, chunkCount, chunkSize, plaintextSize}` |
| `wrapped_item_key`, `payload_version` | | |
| `storage_key` | string | random UUID, **no extension** |
| `storage_disk` | string | |
| `ciphertext_size` | bigint | plaintext — needed for quotas and billing-free accounting |
| `nonce_prefix` | binary(8) | per-file AES-GCM nonce prefix; not secret |
| `uploaded_at` | timestamp null | null until all chunks land; drives orphan cleanup |
| `timestamps`, `deleted_at` | | |

**Leaks:** file size to within a chunk. Unlike payloads, file bodies are not padded — padding a
2 GB upload is not worth it — so sizes are a real fingerprint. Named in the threat model.
Filename, type and hash are all in the payload; 2017 stored `original_name`, `file_type` and
`extension` as plaintext columns.

### `audit_events` (Phase 7)

| Column | Type | Notes |
| --- | --- | --- |
| `id` | bigint PK | |
| `seq` | bigint unique | gapless, allocated under a row lock |
| `prev_hash` | binary(32) | genesis = 32 zero bytes |
| `hash` | binary(32) | `BLAKE2b(prev_hash ‖ canonical_json(entry))` |
| `actor_id` | FK null | null for system events |
| `action` | string | `vault.unlocked`, `secret.viewed`, `membership.granted`, … |
| `subject_type`, `subject_uuid` | | polymorphic |
| `metadata` | jsonb | **structural only** — never payload content |
| `actor_signature` | binary(64) null | Ed25519, for client-originated events |
| `ip_hash` | binary(32) | `HMAC(APP_KEY, ip)` — correlatable, not a stored address |
| `user_agent_hash` | binary(32) | |
| `created_at` | timestamp | |

Append-only: no `updated_at`, no update route, and a database-level revoke of `UPDATE`/`DELETE`
for the application role in production. A `metadata` linter test asserts no key ever holds
decrypted content — the obvious way this table quietly becomes a plaintext leak.

### `share_links` (Phase 9)

| Column | Type | Notes |
| --- | --- | --- |
| `id` / `uuid` | | |
| `token_hash` | binary(32) unique | `BLAKE2b(token)`; the token itself is never stored |
| `payload_ct` | binary | the secret re-encrypted under the link key — which the server never sees |
| `created_by` | FK | |
| `secret_id` | FK null | nulled on secret delete; the link keeps working, by design |
| `expires_at` | timestamp | |
| `max_views`, `view_count` | int | |
| `revoked_at` | timestamp null | |
| `created_at` | timestamp | |

A scheduled job hard-deletes expired and exhausted rows. `payload_ct` here is encrypted under the
**link key**, which lives only in the URL fragment — a different key from everything else in the
system, and worth a comment in the model.

### Supporting tables

- `invites` — `email`, `token_hash`, `invited_by`, `expires_at`, `accepted_at`. Carries **no key
  material** (D8); it authorises account creation only.
- `sessions` — Laravel's default (`SESSION_DRIVER=database`), with `SESSION_ENCRYPT=true` and
  `SameSite=Strict`.
- `password_reset_tokens` — **deliberately unused.** There is no password reset, because the
  server cannot re-wrap a User Key it cannot unwrap. The route returns a page explaining the
  recovery kit. Dropping the table entirely is the honest option; keeping it empty invites a
  future contributor to wire it up.

## Cascade and deletion semantics

- Vault delete → soft delete, 30-day grace, then a job hard-deletes lockboxes, secrets, versions,
  file rows **and object storage blobs**. Orphaned ciphertext in S3 is the classic miss.

  **A soft delete hides the parent and leaves the children routable.** During the grace period the
  lockboxes and secrets of a deleted vault are still live rows with valid UUIDs, so an identifier
  captured before the delete would still resolve. Every policy therefore checks the whole chain
  above a record for deletion, not just the record itself, and the parent relations are declared
  `withTrashed()` so that a deleted parent is a state to test rather than a null to trip over.
  Covered by the IDOR suite.
- User delete → their memberships go, and vaults they solely own enter the grace period. Vaults
  with other members must be transferred first, and the UI blocks deletion until they are.
  Their `audit_events` rows are retained with `actor_id` nulled — deleting them would break the
  hash chain, which is the point of the chain.
- Membership revoke → sets `revoked_at` and `vaults.rekey_required_at` in one transaction.

## Indexes

`vault_memberships (user_id, vault_id)` covers the authorisation check on every request.
`lockboxes (vault_id, sort_order)`, `secrets (lockbox_id, sort_order)`,
`audit_events (subject_type, subject_uuid, seq)`, `share_links (token_hash)`.

**No index can exist on any `_ct` column** — the values are indistinguishable from random. This
is the concrete cost of D5, and it is why the client builds the search index.
