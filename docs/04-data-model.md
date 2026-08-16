# 04 — Data Model

Conventions throughout:

- **`_ct` suffix = ciphertext.** An opaque envelope ([03](03-cryptographic-design.md#envelope-format)).
  The server validates length and never parses the contents.
- **`binary(n)` below describes the *decoded* value, not the column type.** Every ciphertext, key
  and signature is stored **base64 in a `text` column**, because Postgres returns `BYTEA` as a
  stream resource while SQLite returns a string — a divergence that would only ever show up in
  production. `App\Support\Ciphertext` is the single place that knows the encoding, and it holds no
  `decrypt()` method by design. See
  [03 § Envelope format](03-cryptographic-design.md#envelope-format).
- **UUIDv7 public identifiers**, generated client-side so AAD can bind to them before insert.
  Auto-increment `id` stays internal and never appears in a URL or an API response.
- **Every table gets a leakage note.** If a column is plaintext, the reason is written down.
- Postgres in production (real `CHECK` constraints, `jsonb`); SQLite is fine for local dev and
  tests, which is the current `.env` default.

## Diagram

```
users ──1:N── user_key_wraps          (password / recovery / [prf] wrappings of the User Key)
  │
  ├──1:1──── user_identities          (X25519 + Ed25519 public keys, encrypted private keys)
  ├──1:1──── user_pin_stores          (encrypted TOFU fingerprint cache)
  ├──1:N──── totp_backup_codes        (hashed, single-use — the second factor's escape hatch)
  │
  └──1:N── vault_memberships ──N:1── vaults
                                       │
                                       └──1:N── lockboxes
                                                  ├──1:N── secrets ──1:N── secret_versions
                                                  └──1:N── files

audit_events   (hash-chained, standalone)
audit_chain    (one row: the chain tip)
share_links    (one-time, standalone)
```

Every table above is migrated. The
TOTP seed itself lives on `users` rather than in a table of its own; there was no second column
worth the join.

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
| `verifier_hash` | string null | slow hash of the **recovery auth key**, for `method=recovery` |
| `label` | string null | e.g. which passkey, once PRF lands |
| `last_used_at` | timestamp null | |

Unique on `(user_id, method, label)`; multiple `prf` rows are allowed later, distinguished by
label. A separate table rather than columns on `users` because the set of unlock methods is
open-ended — this is what makes passkey unlock a data change rather than a migration of the auth
flow.

**`verifier_hash` is what lets the server verify a recovery attempt without being able to complete
one.** The recovery code is split exactly as the password is: one derivation unwraps the User Key
and stays in the browser, the other is sent and stored here as a slow hash. Without the split the
design has no safe option — either the recovery wrapping is handed to anyone who names an address,
or the server receives the code itself and, holding the wrapping already, has the User Key
outright. See [03 § Recovery](03-cryptographic-design.md#recovery).

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
| `pins_ct` | binary | `{ [userUuid]: fingerprintHex }`, encrypted under the User Key; AAD context `user.pins` bound to the owner's UUID |
| `version` | int | optimistic concurrency across devices |

Encrypted so the server cannot see, or quietly add to, whose keys you have verified. It can still
drop the row or serve a stale copy — it holds the bytes — and that is survivable in a way the
alternative is not: **forgetting a pin degrades to a verification prompt; forging one is silent
interception.** Only forging is prevented, and only forging needs to be.

The version is compared inside the `where` of the update, like `secrets.current_version`. Two
devices that each verified somebody while the other was offline must not silently discard one
another's decision — the user was told it was recorded.

Padded before encryption, because the unpadded length is a count of how many people you have
verified.

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
| `history_max_versions` | smallint null | retention; null follows `config/vault.php`, zero keeps none |
| `history_max_age_days` | smallint null | retention; null follows `config/vault.php` |
| `timestamps`, `deleted_at` | | soft deletes |

**Leaks:** existence, ownership, timestamps, how many vaults a user has, and how much history it
keeps. **The name is encrypted** — the single biggest change from 2017, where `vaults.name` was
plaintext.

The two retention columns are the only settings in the application the server can read, and they
have to be: the server is the thing that enforces them, and a retention policy only the client
could read would be a retention policy nothing applies. What they leak is weak — that one vault
keeps no history and another keeps five years of it — and it is recorded under accepted leakage in
[02](02-threat-model.md#accepted-leakage) rather than encrypted.

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
| `grant_payload` | json (text-preserving) | the exact bytes that were signed — stored so signatures stay verifiable if the canonicalisation ever changes |
| `accepted_at` | timestamp null | recipient confirmed the granter's fingerprint |
| `revoked_at` | timestamp null | |

`grant_signature` and `grant_payload` were nullable as built in Phase 3 and are written on every
grant from Phase 5. They stay nullable in the schema, because the vault creator's own membership
has no signature and cannot have one — there is nobody else whose key would be on it. A membership
with no grant is therefore either the owner's, or a row nobody can account for, and the recipient's
client renders the second as a warning rather than as a vault.

**`grant_payload` is stored as the exact signed string and is not cast.** A signature verifies over
bytes, and decoding then re-encoding is free to change the escaping of `/` or of non-ASCII. Every
such change would turn a valid grant into one no recipient can verify, failing in a way that looks
exactly like tampering. Read it as a string; parse a copy if you need the fields.

The same reasoning constrains the column type, which is easy to get wrong in the other direction.
The migration declares `json`, which on Postgres stores the input text verbatim and is therefore
safe. **`jsonb` would not be:** it normalises whitespace, reorders keys and drops duplicates, which
is precisely the re-encoding this column exists to avoid. If the type is ever revisited, `text` is
the honest choice — the value is a signed blob that happens to look like JSON, not a document the
database should have opinions about.

**Re-granting reuses the row**, because `(vault_id, user_id)` is unique. What must not be reused is
`accepted_at`: it is cleared, so a returning member verifies again. The reason somebody was removed
may be the reason their keys should not be trusted.

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
| `payload_ct` | binary | `{type, key, value, notes, totp?, url?}` — **including the type and any TOTP seed** |
| `wrapped_item_key`, `payload_version` | | |
| `linked_lockbox_id` | FK null | the 2017 lockbox-as-a-value feature, kept |
| `sort_order` | int | |
| `current_version` | int | optimistic-concurrency token; mirrors `secret_versions` |
| `timestamps`, `deleted_at` | | |

**`current_version` is also the concurrency token.** An update must carry the version the client
had when it composed the write, and the comparison happens inside the `where` clause of the update
statement rather than as a read followed by a write — a read-then-write leaves a window in which
the other writer commits, which on a concurrent edit is exactly when it matters. The server cannot
merge two versions of a secret: they are ciphertext under different item keys, and merging would
mean reading them. So the only options are to refuse or to lose one silently, and a password that
vanishes without anyone being told is discovered months later at the worst possible moment.

The refusal is a validation error rather than HTTP 409. Inertia reserves 409 for its own
asset-version protocol and answers one with a hard page reload, which would throw the user's
unsaved edit away while telling them nothing.

**The type is inside the payload.** A `type` enum column would tell the server which secrets are
TOTP seeds, which are SSH keys and which are notes — a meaningful targeting signal for free. The
TOTP seed itself is in there for the same reason: a column saying which rows carry one would be a
list of the accounts worth attacking. Codes are generated in the browser
([03 § TOTP](03-cryptographic-design.md#totp-as-a-stored-credential)).

**`linked_lockbox_id` is plaintext** because the server enforces that both ends live in the same
vault, which requires seeing the edge. It leaks graph structure, which is already leaked by the
foreign keys.

**The 2017 `paranoid` flag** is dropped as a column and becomes `payload.paranoid` — a client-side
UI hint (require re-auth to reveal, never auto-copy). It was never a security control.

### `secret_versions`

| Column | Type | Notes |
| --- | --- | --- |
| `id` / `uuid` | | the uuid is the AAD subject the archived payload is sealed against |
| `secret_id` | FK cascade | |
| `version` | int | unique with `secret_id` |
| `payload_ct`, `wrapped_item_key`, `payload_version` | | each version keeps its own item key |
| `created_by` | FK null | who made the edit that superseded it |
| `timestamps` | | `updated_at` moves only when a re-key re-wraps the item key |

Each version carrying its own Item Key means version history survives Vault Key rotation by
re-wrapping, exactly like a live item, and no version is ever re-encrypted.

**An archived version is a separate encryption, not a copy of the column it replaced.** The
browser re-seals the outgoing plaintext under a fresh Item Key bound to the context
`secret.version.payload` at *this row's own UUID*, and posts it alongside the replacement; the
server stores what it is given and could not produce it itself.

The cheaper design — have the server copy `secrets.payload_ct` across on update — is the one that
must not be built. Copied bytes carry the associated data they were sealed with, which binds them
to `secret.payload` at the secret's UUID: byte-for-byte the binding the live column has. A server
holding both could then write any archived version back over the live row and every client would
verify it happily, silently restoring a password that was rotated *because it leaked*. That is the
attack history creates, and the distinct context and subject are what close it (SR4).

Two consequences, both real and both stated in the interface rather than worked around. An edit
costs one extra sealed payload on the wire. And a secret whose stored ciphertext no longer verifies
cannot be edited at all: an edit has to archive what it replaces, and nothing can archive what it
could not read. Deleting and re-adding is the way past it, and it keeps the unreadable row rather
than overwriting the evidence.

**Retention:** unbounded history is a liability — a password you rotated *because it leaked* stays
recoverable forever. The defaults are in `config/vault.php` (20 versions, 180 days) and either can
be overridden per vault by `vaults.history_max_versions` and `vaults.history_max_age_days`, both
nullable, where null means "follow the deployment default" and zero versions turns history off.

The count is enforced the moment an edit archives a payload, because that is when the count
changes and a bound only a nightly job applied would not be a bound. The age is enforced by
`vault:history-prune`, since nothing about a secret nobody has touched in a year changes until the
clock does. Shortening a vault's policy prunes what is already stored immediately, because the
person changing it is usually doing it *because* of what is in there.

Beside the policy there is a purge: `DELETE /secrets/{secret}/history` erases one secret's history
now, with no grace period, because a grace period on "erase the leaked password" defeats the
purpose. The audit log records that it happened and how many rows went, never what they held.

### `files`

Mapped by `App\Models\VaultFile` rather than a model called `File`, which would collide with a
Laravel facade and an `Illuminate\Http` class in every controller that touched it.

| Column | Type | Notes |
| --- | --- | --- |
| `id` / `uuid` | | |
| `lockbox_id` | FK cascade | |
| `payload_ct` | binary | `{filename, mime, sha256, chunkCount, chunkSize, plaintextSize, noncePrefix}` |
| `wrapped_item_key`, `payload_version` | | |
| `storage_key` | uuid unique | random, **no extension**, generated server-side |
| `storage_disk` | string | |
| `chunk_count` | int | bounds an index and marks completion — never an AAD input |
| `received_chunks` | binary | one bit per chunk; what the server is still waiting for |
| `ciphertext_size` | bigint | bytes actually written to disk, for quotas |
| `uploaded_at` | timestamp null | null until all chunks land; drives orphan cleanup |
| `sort_order` | int | |
| `timestamps`, `deleted_at` | | |

**`ciphertext_size` is the stored ciphertext, not the plaintext.** An earlier draft of this table
described it as the plaintext size, which the client declares — and a quota enforced against a
number the client supplies is not a quota. The plaintext size is in the manifest, where the server
cannot read it and does not need to.

**`received_chunks` is a bitmap, not a counter.** Chunk uploads are idempotent `PUT`s, so a client
retrying one whose response it never saw would advance a counter a second time and declare an
incomplete file finished. A bitmap cannot be double-counted, and it also answers *which* chunks
are missing, which is what a resumed upload needs.

**`chunk_count` is the server's copy and only ever the server's.** The number a client builds a
chunk AAD from comes out of the encrypted manifest. If the two disagree, the manifest is right —
a server that could shrink the count a client verified against could truncate a file undetectably,
which is exactly what binding the count into each chunk's AAD exists to prevent.

**There is no `nonce_prefix` column.** It was specified as one and lives in the manifest instead:
it is not secret, but the client that computes a nonce should be the only party that has seen the
ingredients, and a column would earn nothing for the exposure.

**Leaks:** file size to within a chunk from `chunk_count`, and to the byte from `ciphertext_size`.
Unlike payloads, file bodies are not padded — padding a 100 MiB upload would mean storing and
transferring an arbitrary amount of nothing — so sizes are a real fingerprint. Named in the threat
model. Filename, type and hash are all in the payload; 2017 stored `original_name`, `file_type`
and `extension` as plaintext columns and wrote the upload to disk under a name derived from the
original, so a directory listing was a table of contents.

### `audit_chain`

One row, forever: `seq` and `head_hash`, the tip of the chain.

It exists so that allocating `seq` has something to lock. Locking the last *event* instead is racy
for inserts — a blocked transaction rechecks the row it waited on rather than the new maximum, so
two writers compute the same next sequence — and it makes reading the head an index scan rather
than a lookup. The unique index on `audit_events.seq` is the backstop underneath: if the lock is
ever bypassed, the second insert fails loudly instead of forking the chain.

It is also what notices a chain truncated from the *end*, which nothing else can: what remains
after a truncation is a perfectly valid shorter chain.

### `audit_events`

| Column | Type | Notes |
| --- | --- | --- |
| `id` | bigint PK | |
| `seq` | bigint unique | gapless, allocated under the `audit_chain` row lock |
| `prev_hash` | binary(32) | genesis = 32 zero bytes |
| `hash` | binary(32) | `BLAKE2b(prev_hash ‖ canonical(entry))` — [03 § Audit chain](03-cryptographic-design.md#audit-chain-d9) |
| `actor_uuid` | uuid null | **not a foreign key**; null for system events |
| `action` | string | `vault.unlocked`, `secret.revealed`, `membership.granted`, … |
| `subject_type`, `subject_uuid` | | polymorphic, by UUID |
| `metadata` | text | canonical JSON, **structural only** — never payload content |
| `actor_signature` | binary(64) null | Ed25519, for client-originated events |
| `signed_payload` | text null | the exact bytes that were signed |
| `ip_hash` | binary(32) null | `HMAC(APP_KEY, ip)` — correlatable, not a stored address |
| `user_agent_hash` | binary(32) null | |
| `created_at` | timestamp | second precision; settled before the hash is computed |

**`actor_uuid` is not a foreign key, and that is the point.** A nullable FK with `nullOnDelete`
would mean closing an account silently rewrites every row that account ever touched — which changes
the bytes those rows were hashed over and breaks the chain from the earliest of them. The log would
then report tampering because somebody left. `subject_uuid` is polymorphic by UUID for the same
reason: the record of what happened to a thing has to outlive the thing.

**`metadata` is `text` holding canonical JSON, not `json` or `jsonb`.** The chain hashes those bytes
exactly as stored; a column type that reordered keys or normalised whitespace would invalidate every
hash from that row on. Identical trap to `vault_memberships.grant_payload`. Keys are sorted before
encoding, so the same facts always produce the same bytes.

**The keys are a closed set** (`App\Support\AuditMetadata`), each declaring the shape it holds. This
is the guard on the most likely way this project leaks plaintext: everywhere else a value reaching
the server is already ciphertext, and here there is a free-form JSON column beside a controller with
the whole request in scope. The rule for admission — *could this value differ between two users who
did the same thing to different data?* A role, an epoch, a count and a chunk index cannot. A name, a
note, a filename or a URL can, and none is admissible.

Append-only: no `updated_at`, no update route, a model that throws on update or delete, and a
database-level revoke for the application role in production:

```sql
REVOKE UPDATE, DELETE ON audit_events FROM vault_app;
```

Three layers because the first two are code, and code is changed by whoever is changing the code.

### `share_links`

| Column | Type | Notes |
| --- | --- | --- |
| `id` / `uuid` | | |
| `token_hash` | string(64) unique | base64 `BLAKE2b(token)`; the token itself is never stored |
| `payload_ct`, `payload_version` | | the secret re-encrypted under the link key |
| `created_by` | FK cascade | |
| `secret_id` | FK null | nulled on secret delete; the link keeps working, by design |
| `expires_at` | timestamp | mandatory, and bounded by `vault.share_links.max_hours` |
| `max_views`, `view_count` | int | |
| `revoked_at` | timestamp null | |
| `created_at` | timestamp | no `updated_at` — see below |

`vault:links-prune` hard-deletes expired, revoked and exhausted rows, hourly rather than nightly: a
share link is a credential in somebody else's inbox, and the gap between "cannot be opened" and
"no longer exists" should be short. Nothing here is recoverable and nothing should be, which is what
separates this sweep from the file one — a purged file waits out a grace period *because it might be
restored*, and a spent link has no such state.

**`token_hash` is `string`, not the `text` every other opaque value uses.** It is the one indexed
one, and MySQL cannot put a unique index on a TEXT column without a prefix length. It is a fixed 44
characters, so a varchar costs nothing and is portable.

**`payload_ct` is encrypted under a key from outside the hierarchy.** It is the only ciphertext in
the schema that no Vault Key opens, and that is the point: a share must not be openable with a vault
key, or handing over one secret would hand over the means to read the vault it came from. This is
the concrete payoff of giving every item its own key.

**There is no `updated_at`.** The only column that moves after creation is `view_count`, and a
timestamp beside it would record when a stranger opened the link — the kind of fact the audit log
should hold deliberately rather than a row should accumulate by accident.

`/account/links` renders the rows a user may withdraw, which is exactly the set
`ShareLinkPolicy::revoke` allows: their own, plus any issued into a vault they administer. The
`secret_id` foreign key is what makes the second half answerable, and it is why the relation is
`nullOnDelete` rather than cascading — the row survives its secret, and the page says so.

**The token reaches the server only in a request body**, never a path segment, because a path
segment is written to every access log in front of the application in the clear. The creator's
browser sends the *hash* and the recipient's browser sends the *token*; reversing either would put a
working credential somewhere it does not need to be. See
[03 § One-time share links](03-cryptographic-design.md#one-time-share-links-d9).

### Supporting tables

- `invites` — `email`, `token_hash`, `invited_by`, `expires_at`, `accepted_at`. Carries **no key
  material** (D8); it authorises account creation only.
- `totp_backup_codes` — one row per code, stored hashed and marked as used rather than deleted, so
  a user can see that a code was spent. Guards *authentication only*: a second factor cannot gate
  decryption, because decryption does not involve the server.
- `sessions` — Laravel's default (`SESSION_DRIVER=database`), with `SESSION_ENCRYPT=true` and
  `SameSite=Strict`.
- `password_reset_tokens` — **dropped, not merely unused.** There is no password reset, because the
  server cannot re-wrap a User Key it cannot unwrap, and the route returns a page explaining the
  recovery kit instead. Keeping the table empty would have invited a future contributor to wire it
  up; removing it means the schema itself says there is nothing to wire.

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

  **`DELETE /vaults/{vault}` refuses while any live membership other than the caller's exists**, and
  the refusal is a validation error rather than a 403 — the caller is an authorised administrator
  being told about state, not a stranger probing an identifier. A membership row is a sealed copy of
  the Vault Key, so deleting the vault under its other members withdraws their access by a route
  that never mentions access, and leaves none of the trail a revocation would. Revoked rows are not
  counted: that access was already cut, and a guard that never releases would make any vault that
  had ever been shared permanently undeletable.
- Ownership transfer → `PATCH /vaults/{vault}/owner` moves `vaults.owner_id`, promotes the
  recipient's membership to `owner` and demotes the caller's to `editor`, in one transaction with
  the vault row locked so that two administrators acting at once cannot produce two owners. **No
  ciphertext changes and `key_epoch` does not move**, because the recipient has held a sealed Vault
  Key since they were granted access — transfer moves an authorisation fact, not a cryptographic
  one. The recipient must be a live member, at the current epoch, with `accepted_at` set. The
  outgoing owner keeps their sealed key and can still decrypt everything; only revocation plus a
  re-key changes that.
- Secret delete → soft delete; its versions stay, because a restorable secret with no history
  would come back missing most of what it was. A hard delete cascades them.
- Membership revoke → sets `revoked_at` and `vaults.rekey_required_at` in one transaction.

## Indexes

`vault_memberships (user_id, vault_id)` covers the authorisation check on every request.
`lockboxes (vault_id, sort_order)`, `secrets (lockbox_id, sort_order)`,
`audit_events (subject_type, subject_uuid, seq)`, `share_links (token_hash)`.

**No index can exist on any `_ct` column** — the values are indistinguishable from random. This
is the concrete cost of D5, and it is why the client builds the search index.
