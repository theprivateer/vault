# 03 — Cryptographic Design

The specification. The implementation follows this document and nothing else; if reality forces a
change, this document changes first and the code second. Sections describing work not yet built
say which phase owns them.

## Primitives

| Purpose | Algorithm | Implementation |
| --- | --- | --- |
| Password stretching | Argon2id, m=64 MiB, t=3, p=1, 64-byte output | `@noble/hashes/argon2` (see [KDF performance](#kdf-performance)) |
| Key derivation from high-entropy input | HKDF-SHA-256 | `@noble/hashes/hkdf` |
| Authenticated encryption | XChaCha20-Poly1305 (192-bit nonce) | `@noble/ciphers/chacha` |
| Bulk file encryption | AES-256-GCM, chunked | WebCrypto (hardware accelerated) |
| Key agreement / sealing | X25519 sealed box | `@noble/curves/ed25519` + `@noble/ciphers` |
| Signatures | Ed25519 | `@noble/curves/ed25519` |
| Hashing, fingerprints, audit chain | BLAKE2b-256 | `@noble/hashes/blake2` |
| Randomness | `crypto.getRandomValues()` | WebCrypto |
| Server-side auth key hashing | Argon2id, m=32 MiB, t=2, p=1 | PHP `ext-sodium` via Laravel's `argon2id` hash driver |

**Why XChaCha20-Poly1305 over AES-GCM for the envelope.** A 192-bit nonce can be generated
randomly with no practical collision risk, which removes an entire class of counter-management
bugs. AES-GCM's 96-bit nonce is safe with random generation at this volume, but only because the
volume is low — that is a constraint to remember rather than a property of the design. Files are
the exception: they are large, throughput matters, and WebCrypto's AES-GCM is hardware
accelerated, so chunked AES-GCM with explicit counter management is used there and the counter
discipline is tested directly.

**Why `@noble/*`.** Audited, pure TypeScript, no WASM (so no `wasm-unsafe-eval` in the CSP —
a real interaction between D10 and this choice), no transitive dependencies, no post-install
scripts. The whole crypto dependency surface is three packages that can be read end to end.

### KDF performance

The budget, set before anything was built on it: **under 2 s on a modern laptop, under 5 s on a
mid-range phone.** The concern was that pure-JS Argon2id at 64 MiB / t=3 would miss it, forcing a
swap to `hash-wasm` and with it `'wasm-unsafe-eval'` in `script-src` — a slower unlock versus a
looser CSP, which is a trade to make with measurements in hand rather than by guesswork.

**Measured, and the question is closed.** `@noble/hashes` 2.3.0 at the specified parameters runs
in **731 ms** on an Apple M1 (`npm run bench:argon2`, five runs after a warm-up). That is
comfortably inside the laptop budget, so no second implementation needed evaluating and the CSP
keeps no `'wasm-unsafe-eval'`. The reasoning and the rejected alternatives are in
[ADR-0003](adr/0003-argon2id-implementation.md).

Two things still hold:

- All KDF work runs in the **crypto Web Worker**, so the main thread stays responsive and can show
  real progress. This is needed anyway for key isolation (see
  [Key handling in memory](#key-handling-in-memory)).
- **The phone figure is still an estimate, not a measurement.** A mid-range phone is typically 2–4×
  slower than an M1, which puts unlock at roughly 1.5–3 s — inside the budget, but nobody has run
  it on a real device. Outstanding; it reopens the WASM question only if it comes in above 5 s.

Parameters are stored per-user in the database so they can be raised later without a flag day;
see [Parameter upgrades](#parameter-upgrades).

## Key hierarchy

```
                    master password (user's head)
                              │
                    Argon2id(pw, kdfSalt, m=64MiB, t=3, p=1) → 64 bytes
                              │
              ┌───────────────┴────────────────┐
         bytes[0..32]                     bytes[32..64]
              │                                │
            KEK                             AuthKey ──TLS──> server
      (never leaves device)                             stores Argon2id(AuthKey)
              │
              │ unwraps                    recovery code (128-bit, shown once)
              ▼                                │
                                          HKDF-SHA256 → RecoveryKEK
      ┌─── User Key (random 32B) ───────────────┘  (also unwraps User Key)
      │
      │ encrypts
      ├──> X25519 private key   (receive sealed Vault Keys)
      └──> Ed25519 private key  (sign grants, audit entries)

      Vault Key (random 32B, one per vault)
        └── sealed to each member's X25519 public key → vault_memberships.wrapped_vault_key
              │
              │ wraps
              ▼
      Item Key (random 32B, one per lockbox / secret / file)
              │
              │ encrypts
              ▼
      payload_ct  — the item's fields as JSON
```

**Why the User Key exists** rather than encrypting private keys directly under the KEK: a password
change then re-wraps one 32-byte key instead of re-encrypting anything. The same reason the
recovery code wraps the User Key rather than being a second password.

**Why per-item keys** (D7): rotating a Vault Key means re-wrapping N 32-byte item keys, which the
client can do in one batch, rather than downloading, decrypting and re-encrypting every payload.
It also lets a single item be shared (one-time links) without exposing the Vault Key.

## Envelope format

Every ciphertext at rest, other than file bodies, uses one binary envelope:

```
┌────────┬────────┬──────────────┬───────────────────────┬──────────┐
│ ver    │ alg    │ nonce        │ ciphertext            │ tag      │
│ 1 byte │ 1 byte │ 24 bytes     │ variable              │ 16 bytes │
└────────┴────────┴──────────────┴───────────────────────┴──────────┘
  0x01     0x01 = XChaCha20-Poly1305
```

`ver` allows the envelope structure to change; `alg` allows the primitive to change. A decryptor
rejects anything it does not recognise with a specific error — never a silent fallback.

**Stored base64-encoded in `text` columns, not as `BLOB`/`BYTEA`.** Postgres hands `BYTEA` back as
a stream resource while SQLite hands back a string, and that difference would surface only in
production, on the one type nobody wants surprises from. The 33% overhead is irrelevant at these
sizes because file bodies live in object storage rather than the database. `App\Support\Ciphertext`
is the only thing that touches the encoding, and it re-encodes on the way in so the stored form is
canonical regardless of what padding or whitespace a client sent.

### Associated data binding

**Every** `seal()` call passes AAD, and the AAD is canonical:

```
AAD = "vault.v1" ‖ 0x00 ‖ context ‖ 0x00 ‖ subject_uuid ‖ 0x00 ‖ payload_version
```

- `context` — a fixed string per use, e.g. `secret.payload`, `lockbox.payload`,
  `vault.membership.key`, `item.key`, `user.privkey.x25519`, `file.chunk`.
- `subject_uuid` — the UUID of the row the ciphertext belongs to.
- `payload_version` — the schema version of the JSON inside.

This is what makes SR4 true. Without it, a malicious server can take the ciphertext of a
low-value secret and write it over a high-value one, or swap a `viewer`'s wrapped key for an
`owner`'s, and the client decrypts happily. With it, the tag check fails and the client shows an
integrity error naming the record. It is three lines of code and it closes a whole attack class.

#### Which subject, and which version

Settled in Phase 3, because "the UUID of the row" is ambiguous the moment one row holds two
ciphertexts:

| Context | `subject_uuid` | `version` |
| --- | --- | --- |
| `vault.payload`, `lockbox.payload`, `secret.payload` | the item's own UUID | `payload_version` |
| `secret.version.payload` | the **version row's** UUID, not the secret's | `payload_version` |
| `item.key` | the UUID of the item the key belongs to | `1`, fixed |
| `vault.membership.key` | the **membership** UUID, not the vault's | `1`, fixed |
| `user.userkey`, `user.privkey.*` | the user's UUID | `1`, fixed |

Three decisions worth stating outright:

- **A wrapped key binds to the membership row, not the vault.** Binding to the vault would let a
  server copy one member's sealed Vault Key onto another member's row — which is the substitution
  named above, unprevented. Binding to the membership makes that a tag failure.
- **Key wrappings pin `version` at 1 rather than following `payload_version`.** A wrapped key is
  32 bytes and has no schema to evolve. Tying it to the payload version would change an item key's
  binding every time an unrelated field was added to the JSON beside it, for no benefit.
- **An archived version gets its own context *and* its own subject.** Both are load-bearing, and
  the reason is the whole of [Version history](#version-history) below.

### Payload padding

Item payloads are padded to a bucket size *before* they are sealed. AEAD ciphertext is exactly as
long as its plaintext plus fixed overhead, so an unpadded payload publishes the length of the
secret inside it to anyone holding the database.

```
padded = plaintext ‖ 0x80 ‖ 0x00 …        to the next bucket
buckets = 64, 128, 256, 512, 1024, 2048, 4096, then multiples of 4096
```

Three choices worth naming:

- **ISO/IEC 7816-4 delimiter rather than a length prefix.** The delimiter is always written, so
  the encoding is unambiguous even for a plaintext ending in `0x00` or `0x80`, and unpadding
  cannot be made to read past the end of the buffer the way a corrupted length prefix can. It
  costs one byte more.
- **Inside the AEAD, not around it.** The padding is covered by the tag, so a server cannot strip
  it back off to recover the original length.
- **Buckets rather than one fixed size.** A single size hides length completely and makes a
  60-byte password cost as much to store as a 4 KiB note. The buckets keep worst-case waste under
  50% and collapse the whole realistic range of credentials into five sizes. What still leaks is
  the bucket, and that is written down in [02 § Accepted leakage](02-threat-model.md#accepted-leakage).

**Padding is what `payload_version` 2 means.** There is no safe way to detect padding after the
fact — an unpadded v1 payload run through the unpad routine would either throw or, worse,
silently truncate a secret whose last byte happened to be `0x80`. So the reader is told by the
version, and because the version is bound into the AAD, a server cannot relabel a v2 payload as
v1 to get the old handling. Version 1 is read and never written.

#### The client builds the AAD, always

The server sends ciphertext, UUIDs and version numbers. It never sends associated data, and the
client never accepts any: each AAD is reconstructed in the browser from the record it is holding.

This is not a detail. A server that could name the AAD could hand over one record's ciphertext
along with instructions to verify it against a different record — which defeats precisely the
binding this section exists to establish. Deriving the AAD from the record's own identifier means
relocating a ciphertext requires relocating its identifier too, and that makes it a different
record rather than a substituted one.

### Errors are loud

The 2017 code caught `DecryptException` and returned `null`. The rebuild does the inverse:

- `IntegrityError` — the tag failed. Names the record and the context. Surfaces as a red banner:
  *"This item could not be verified and may have been tampered with."* Never rendered as empty.
- `UnsupportedEnvelopeError` — unknown `ver`/`alg`.
- `KeyUnavailableError` — no key in the chain to decrypt this.

A decrypt function never returns `null` or `undefined` on failure. It throws.

## Protocol flows

### Registration

Registration is invite-only (D11). The invite carries no key material — it authorises account
creation, nothing more.

**Client:**
1. `kdfSalt` ← 16 random bytes.
2. `stretched` ← `Argon2id(password, kdfSalt, m=64MiB, t=3, p=1, 64)`.
   `KEK` = `stretched[0..32]`, `authKey` = `stretched[32..64]`.
3. `userKey` ← 32 random bytes.
4. `(x25519_pk, x25519_sk)`, `(ed25519_pk, ed25519_sk)` ← generated.
5. `recoveryCode` ← 16 random bytes, rendered as 26 Crockford-base32 characters in groups of 4.
   `recoverySalt` ← 16 random bytes. `RecoveryKEK` = `HKDF-SHA256(recoveryCode, recoverySalt,
   info="vault:recovery:v1")`.
   *No Argon2 here* — the input is already 128 bits of uniform randomness, so a slow KDF buys
   nothing. Using Argon2id for the password and HKDF for the recovery code is the correct
   distinction, not an inconsistency.
6. Wrap: `AEAD(KEK, userKey)`, `AEAD(RecoveryKEK, userKey)`,
   `AEAD(userKey, x25519_sk)`, `AEAD(userKey, ed25519_sk)`.
7. `fingerprint` = `BLAKE2b-256(ed25519_pk ‖ x25519_pk)`, rendered as six 4-character groups.
8. Self-sign the public keys with `ed25519_sk`, so a client can verify the two public keys were
   published together by the holder of the private key.
9. POST: `authKey`, `kdfSalt`, KDF params, `recoverySalt`, both wrapped User Keys, both public
   keys, both encrypted private keys, the self-signature, and the fingerprint.

**Server:** stores `Argon2id(authKey)` — a *slow* hash, because `authKey` inherits only the
password's entropy, not 256 bits — plus every blob above, opaque.

**UI:** the recovery kit is displayed once, on its own screen, with a print stylesheet, a copy
button, and a checkbox the user must tick: *"I understand that if I lose both my password and
this recovery kit, my data cannot be recovered by anyone, including the administrator of this
server."*

### Login and unlock

Two distinct states, and the distinction matters: **authenticated** (the server knows who you
are, you have a session) and **unlocked** (your browser holds the User Key). You can be
authenticated and locked; you can never be unlocked without being authenticated.

1. `POST /auth/kdf-params { email }` → `{ kdfSalt, params }`.
   **User-enumeration hazard.** For an unknown email the server must return plausible, stable,
   deterministic values: `kdfSalt = HKDF(APP_KEY, "kdf-salt-decoy" ‖ lowercase(email))[0..16]`
   with the current default params, in constant time. Same shape, same latency, no distinction.
   Rate limited per IP.
2. Client derives `KEK` and `authKey`.
3. `POST /auth/login { email, authKey }` → session cookie, plus (on a second factor, if enabled,
   a TOTP challenge first) the wrapped User Key, encrypted private keys and KDF metadata.
4. Client unwraps `userKey` with `KEK`, then the private keys with `userKey`. All of this happens
   inside the crypto Worker; the main thread receives a handle, never the bytes.
5. Failure to unwrap is reported as "incorrect password" without a server round trip — the server
   cannot distinguish and does not need to.

### Recovery

**The recovery code is split, exactly as the password is.** Two keys are derived from it with
HKDF under different `info` strings:

- `RecoveryKEK = HKDF(code, salt, info="vault:recovery:enc:v1")` — unwraps the User Key, stays in
  the browser.
- `RecoveryAuthKey = HKDF(code, salt, info="vault:recovery:auth:v1")` — sent to the server, which
  stores only a slow hash of it in `user_key_wraps.verifier_hash`.

This split is not cosmetic symmetry with D4; without it the design has no safe option. Either the
server hands the recovery wrapping to anyone who names an address — letting an attacker overwrite
that account's password wrapping and lock the owner out — or it receives the code itself, which
combined with the wrapping it already holds gives it the User Key outright. Splitting the code
lets the server *verify* a recovery attempt while still being unable to complete one.

Found while implementing Phase 2; the flow below reflects the corrected design.

Recovery is then two steps, mirroring login: `POST /recover/salt` returns the salt (with a stable
decoy for unknown addresses), and `POST /recover` proves possession with the auth key and returns
the wrapping. Step 2 uses `RecoveryKEK` to unwrap the User Key, client-side.
On success, the user is **required** to set a new password before continuing, which re-wraps the
User Key under the new KEK. The old recovery code is invalidated and a fresh kit is issued, since
it has now been typed into a browser and possibly a password manager, a screenshot and a
clipboard history. Every use is a high-severity audit event and triggers an email notification.

### Password change

1. Unlock with the old password (already unlocked in practice).
2. Derive new `KEK'` and `authKey'` from the new password and a **fresh** `kdfSalt'`.
3. Re-wrap `userKey` under `KEK'`.
4. `POST` the new salt, params, `authKey'`, and re-wrapped User Key, authenticated by the old
   `authKey`, in a single transaction.

Nothing else re-encrypts. Vault Keys, Item Keys and payloads are untouched. This is the payoff
from the User Key indirection.

### Creating a vault

1. `vaultKey` ← 32 random bytes.
2. Payload `{name, description}` → `itemKey` ← 32 random bytes; `payload_ct = AEAD(itemKey,
   json, aad("vault.payload", uuid, v))`; `wrapped_item_key = AEAD(vaultKey, itemKey, aad(...))`.
3. Owner's membership row: `wrapped_vault_key = seal(vaultKey, self.x25519_pk)`, `role=owner`,
   `key_epoch=1`.

The client generates the UUID (UUIDv7) so that AAD can bind to it before the row exists — a small
but necessary ordering detail. The server validates the UUID's version and uniqueness.

### Sharing a vault (D8)

1. Owner requests `GET /users/{handle}/identity` → public keys, self-signature, fingerprint.
2. Client verifies the self-signature, then checks its **local pin store** (a TOFU cache of
   fingerprints seen before, itself encrypted under the User Key and synced as an opaque blob).
   - Never seen → show the fingerprint and require explicit confirmation, with a prompt to verify
     it out of band.
   - Seen and matching → proceed silently.
   - **Seen and changed → hard stop.** A red interstitial, no "continue anyway" on the first
     click, and a high-severity audit event. This is precisely what a server substituting its own
     key looks like.
3. `wrapped = seal(vaultKey, recipient.x25519_pk)`.
4. `grant = { vaultUuid, recipientUuid, recipientFingerprint, role, keyEpoch, grantedAt }`;
   `signature = Ed25519_sign(granter.sk, canonical_json(grant))` — see
   [the grant format](#the-grant-format) for the exact bytes.
5. POST the wrapped key, the grant and the signature.
6. The recipient's client **verifies the signature against the granter's pinned public key**
   before trusting the vault. A server-fabricated membership row has no valid signature.

The sealed box is: ephemeral X25519 keypair → `ECDH(eph_sk, recipient_pk)` →
`HKDF-SHA256(shared ‖ eph_pk ‖ recipient_pk, info="vault:seal:v1")` → XChaCha20-Poly1305.
Stored as `eph_pk ‖ envelope`. Anonymous to the recipient by construction, which is why the
separate signed grant carries the sender's identity.

#### The grant format

Settled in Phase 5. The signed bytes are canonical JSON with a fixed field order:

```
"vault:grant:v1" ‖ 0x00 ‖ {"v":1,"vaultUuid":…,"recipientUuid":…,
                           "recipientFingerprint":…,"role":…,"keyEpoch":…,"grantedAt":…}
```

Four decisions in that line, each of which closes something:

- **A domain separator.** A self-signature, a grant and (in Phase 7) an audit entry are all
  Ed25519 signatures by the same key. Without a prefix, one could be replayed as another.
- **The recipient's fingerprint is inside the signature.** Binding to the account alone would let
  a server substitute the recipient's public key and replay an otherwise genuine grant against
  it. Naming the keys means a grant is only valid for the keys it was issued for.
- **`keyEpoch` is inside it too.** A grant issued before a rotation does not authorise a
  membership after one.
- **The exact bytes are stored, not the fields.** `vault_memberships.grant_payload` holds the
  canonical JSON verbatim, so a future change to the serialisation cannot invalidate signatures
  already issued. It is deliberately *not* cast to an array on the model: a round trip through
  `json_decode`/`json_encode` is free to change the escaping of `/` or of non-ASCII, and every
  such change would turn a valid grant into one no recipient can verify — failing in a way that
  looks exactly like tampering.

**Verifying a grant is two checks, not one.** The signature proves the granter signed *some*
grant. Comparing the signed fields against the membership row on offer is what makes it evidence
about *this* row — otherwise a server holding any genuine grant could staple it to a fabricated
membership with a role of its choosing. `grantedAt` is excluded from that comparison: it is the
granter's claim about when they acted, and comparing it would turn clock skew into a tampering
report.

The server compares the two as well, when a grant is written. That check is worth nothing against
a malicious server, which would simply skip it; it exists to catch a client that built the grant
wrong, at the moment the mistake is made rather than weeks later when nobody can say why the
recipient cannot accept.

#### The pin store

`user_pin_stores.pins_ct` holds `{ [userUuid]: fingerprintHex }`, sealed under the User Key with
AAD context `user.pins` bound to the owner's own UUID, and padded like an item payload — the
unpadded length would count how many people you have verified.

The asymmetry that makes this work is worth stating plainly: the server can **forget** a pin and
cannot **forge** one. Forgetting degrades to a verification prompt, which is safe. Forging would
mark the server's own substituted key as already trusted, which is the entire attack. Only the
second is prevented, and only the second needs to be.

The client fails closed to match. A pin store that will not decrypt is not treated as an empty
one: every identity reports as unverified, so the user is asked to check again rather than told
everything is fine on the strength of a store nobody could read.

#### The identicon

A fingerprint is also drawn as a 7×7 mirrored grid derived from `BLAKE2b(fingerprint)`, because
people notice a shape changing and do not reliably compare 24 characters of base32.

**It is an aid, not the check, and the difference is quantitative.** The grid encodes 56 bits, and
a symmetric grid is a birthday problem, so an attacker willing to grind roughly 2²⁸ keypairs —
minutes of work — could produce a different identity that draws the same picture. Every place it
appears therefore shows the characters beside it, and the wording asks the user to compare those.

#### Degenerate public keys

**Small-order public keys must be rejected.** Ed25519 verification accepts an all-zero signature
against an all-zero public key, for any message. Without an explicit check, a malicious server
could publish a degenerate identity whose self-signature verifies — defeating the exact check
that exists to detect key substitution. Identity verification therefore rejects all eight points
of the Ed25519 torsion subgroup (`ED25519_TORSION_SUBGROUP`, which includes the all-zero
encoding) and the all-zero X25519 key. X25519's own small-order points are refused by
`getSharedSecret` at the point of use.

Verification of untrusted keys **never throws**: malformed, degenerate and simply-wrong input all
return `false`, to be rendered as a warning. Signing throws on bad input, because that is our own
data. Found and fixed during Phase 1; see `identity.ts`.

### Revocation and rotation

Revocation without rotation is theatre — the removed member's client may have cached the Vault
Key. So revocation *is* rotation:

1. Server marks the membership revoked immediately (cuts off API access first, since that part is
   instant and enforceable).
2. An owner's client, on next unlock, is told the vault needs re-keying.
3. It generates `vaultKey'`, fetches all item keys for the vault, unwraps each under `vaultKey`,
   re-wraps each under `vaultKey'`, seals `vaultKey'` to each **remaining** member, and submits
   the whole set with `key_epoch + 1` in **one atomic request**. The server accepts it only if
   the epoch is exactly current+1 and the item key set is complete — a partial re-key is rejected
   rather than half-applied. This is the resumability failure of the 2017 `vault:key` command,
   fixed by making the operation atomic instead of incremental.
4. Payload ciphertexts are untouched. For a vault with 500 items this is 500 × 32 bytes of
   re-wrapping — milliseconds — versus re-encrypting every payload.

**Stated in the UI:** rotation prevents future access. It cannot retract what was already read.

Three details settled while building it in Phase 5:

- **Trashed items are re-keyed too.** During the 30-day grace period a soft-deleted lockbox or
  secret is still a row holding an item key wrapped under the *old* Vault Key. Skipping those
  would quietly turn "deleted, restorable for 30 days" into "deleted", without anyone choosing
  that. The re-key set therefore includes them, and the endpoint that supplies the set includes
  trashed rows.
- **The epoch is compared after the row is locked, not before.** Two owners rotating at once would
  otherwise both read `key_epoch` as 3, both find it acceptable, and the second would overwrite
  the first — leaving members holding a Vault Key that no longer wraps anything.
- **Every remaining member's fingerprint is verified before the rotation runs.** Rotation seals a
  fresh key to each of them, so a member whose public key was substituted since the last check
  would be handed the new key *by this operation*. Without that gate, rotation is a delivery
  mechanism.

"Complete" means exactly complete: nothing missing and nothing extra. A submission naming an item
that is not in the vault is a client working from a stale picture, and the items it did send are
then unlikely to be the whole set either.

### Files

Chunked AES-256-GCM via WebCrypto — the one place this design does not use
XChaCha20-Poly1305. Every target browser implements AES-GCM in hardware, and a 100 MiB upload is
the only operation here where the difference between a hardware cipher and a very good JavaScript
one decides whether there is a progress bar or a hung tab. Payloads are kilobytes and stay on the
audited pure-TS path; the exception is confined to `crypto/chunks.ts`.

- `fileKey` ← 32 random bytes, wrapped by the Vault Key like any other item key. It is unwrapped,
  used and zeroised **per chunk** rather than held: a 500-chunk transfer would otherwise leave a
  live key in the keyring for its whole duration, and one ChaCha20 pass over 32 bytes against a
  mebibyte of AES does not register.
- Chunk size 1 MiB. `nonce = noncePrefix(8 random bytes, per file) ‖ counter(4 bytes BE)`.
  Constructed rather than random because GCM's nonce is 96 bits, which is too short to generate
  randomly at scale — and a repeated nonce under one key is a total break of GCM, not a
  degradation. Counting makes a repeat within a file impossible rather than unlikely.
- **The nonce is not stored with the chunk.** It is derived from the prefix in the manifest and the
  index being requested, so there is no nonce field for a server to substitute and 12 bytes per
  chunk stay off the wire.
- Chunk on the wire: `[ver:1][alg:1][ciphertext ‖ tag:16]`, `alg = 2` for AES-256-GCM. Raw bytes,
  not base64 — a chunk endpoint carries no other fields, so there is nothing JSON would be
  wrapping, and 33% of 100 MiB is the one place the overhead is worth avoiding.
- Per-chunk AAD: `aad("file.chunk", file_uuid, v) ‖ chunk_index ‖ chunk_count`. Binding the index
  and the count is what prevents **truncation and reordering** — an attacker who drops the last
  chunk must otherwise be detected by the application, and here it is detected by the tag.
  The earlier draft of this section also bound an `is_final` flag; it is not implemented, because
  `chunk_index == chunk_count - 1` already determines it and a second encoding of one fact is one
  more thing to get out of step.
- **Both numbers come from the manifest, never from the response.** The manifest is inside
  `payload_ct`, so only a client that has decrypted the file's payload knows how many chunks there
  should be. A client that took the count from the row it is validating would be asking the sender
  to confirm its own claim, and the truncation defence would evaporate.
- The manifest holds `{filename, mime, sha256, chunkCount, chunkSize, plaintextSize, noncePrefix}`.
  All of it is in the encrypted payload, including the nonce prefix — it is not secret, but the
  client that computes a nonce should be the only party that has seen the ingredients, and a column
  for it would earn nothing.
- Filenames live in `payload_ct`. Object storage keys are random UUIDs with no extension, with
  chunks numbered beneath them.
- Upload: encrypt chunk-by-chunk in the Worker, `PUT` each to a chunked endpoint. The row is
  created **before** the first chunk, carrying the sealed manifest and the wrapped File Key, which
  is what makes an interrupted upload resumable rather than merely restartable.
- **Resuming re-encrypts a chunk at a nonce that chunk has already used.** That is safe if and only
  if the bytes are identical, so a resume verifies the source against the manifest's SHA-256 before
  it sends anything. Continuing with different bytes would be nonce reuse under GCM, which leaks
  the XOR of the two plaintexts and the authentication subkey with it.
- Download v1: fetch, decrypt to a `Blob`, hand to the browser. **Cap at ~100 MiB** — the parts are
  themselves Blobs, so the browser may spill them to disk, but the ceiling is real enough to refuse
  at the top rather than discover at chunk 900. Streaming download via a Service Worker +
  `TransformStream` is the stretch goal and lifts the cap; it is *not* built.

### Version history

An edit does not overwrite; it appends. The browser re-seals the payload it is about to replace as
a version of its own and posts both in one request:

1. `versionUuid` ← a fresh UUIDv7, minted before anything is encrypted, because it is the AAD
   subject.
2. `versionKey` ← 32 random bytes. `versionCt = seal(versionKey, pad(oldPayload), aad =
   "secret.version.payload" ‖ versionUuid ‖ payloadVersion)`.
3. `wrap(versionKey)` under the Vault Key, bound as `item.key` at `versionUuid` — the same wrapping
   every other item gets, which is what lets a re-key cover history without re-encrypting it.
4. PATCH the secret with the replacement payload *and* those three values. The server writes both
   rows inside the transaction that guards the optimistic-concurrency check, so a write that loses
   the race leaves no archive behind.

**The archived ciphertext is a new encryption, never a copy of the column it replaced**, and that
is the single decision this feature turns on. Copied bytes would carry the associated data they
were sealed with, binding them to `secret.payload` at the *secret's* UUID — byte-for-byte identical
to the binding the live column has. A server holding both could then write any archived version
back over the live row, and every client would verify it happily. Rolling a rotated credential back
to the one that leaked is the attack that adding history creates; the distinct context and the
per-version subject are what close it. `lib/history.test.ts` runs exactly that substitution and
expects a tag failure.

Two consequences, both stated in the interface rather than worked around:

- An edit costs one extra sealed payload on the wire, roughly doubling the bytes a small secret
  writes.
- **A secret whose stored ciphertext no longer verifies cannot be edited.** An edit has to archive
  what it replaces, and nothing can archive what it could not read. Deleting and re-adding is the
  way past it, and it has the better property anyway: the unreadable row is kept rather than
  overwritten.

A restore is not a separate cryptographic operation. It is an ordinary edit whose plaintext happens
to be old — same endpoint, same concurrency guard, same archive of whatever it replaces — so
"restore is never destructive" is a property of the routing rather than a rule anything has to
remember. Only the audit entry differs.

Diffing is client-side for the usual reason and a slightly sharper one than D5's: the server cannot
compare two ciphertexts sealed under different Item Keys, so the browser is not merely the
preferred place for the comparison, it is the only one.

**Retention is the counterweight**, and the tension is real: history recovers a value somebody
pasted over by mistake, and history of a value rotated *because it leaked* is a copy of the leaked
value kept somewhere convenient. The policy is a count and an age, defaulted in `config/vault.php`
and overridable per vault, plus a purge that erases one secret's history now with no grace period.
Neither is a control against a member — anyone who could read those versions has already read them
— but bytes that no longer exist cannot be in next year's stolen backup. See
[04 § secret_versions](04-data-model.md#secret_versions).

### One-time share links (D9)

The recipient has no account and no keys, so the link itself carries the key:

1. `linkKey` ← 32 random bytes. `token` ← 32 random bytes.
2. Client re-encrypts *just that secret's payload* under `linkKey`, padded to a bucket as any
   stored item is — this is why per-item keys matter; the Vault Key is never involved in the share.
3. POST `{ token_hash: BLAKE2b(token), payload_ct, expires_in_hours, max_views }`. The server never
   receives `token` or `linkKey`.
4. The URL is `https://host/s#{base64url(token)}.{base64url(linkKey)}`. **The fragment is never
   sent to the server** — that is the whole trick.
5. On open, the page reads both halves out of the fragment and POSTs the token to `/s/reveal` in a
   request body. The server hashes it, finds the row, consumes a view inside a locked transaction
   and returns the ciphertext; the browser decrypts with the key that never left the address bar.

**Both halves are in the fragment, which is a change from the original design here.** The token was
specified as a path segment, `/s/{token}`, and that cannot meet the security requirement that no log
holds a token: a path segment is written to every reverse-proxy access log in front of the
application, in the clear, by default, and nothing in this codebase can prevent it. A request body
is not logged by anything by default. That single move turns the requirement from a hope into a
property, and `tests/Feature/Vault/ShareLinkTest.php` sweeps every table and log file to hold it.

It also removes the caveat this section used to end with. A chat client unfurling the link fetches
`GET /s` with no fragment, so **a link preview cannot consume a view** — the token never reaches
the unfurler at all. `max_views` above one is still offered, but now for the honest reason: a
recipient who reloads, or who opens it on a phone after a laptop.

The AAD subject is derived from the token — `BLAKE2b(token)` formatted as a UUID — rather than
transmitted, for the same reason a file chunk's nonce is derived: a value the server supplies is a
value the server can substitute, and the rule is that the client builds every AAD from something
the server did not choose. It is deliberately *not* `share_links.uuid`, which identifies the row for
the server; conflating the two would hand the server the input it must not have.

**The link key is the one key in this system that is meant to leave the device**, so it lives on the
main thread rather than in the Worker. A Worker round trip would imply a containment this feature
does not have, and saying so plainly is better — see `resources/js/crypto/sharelink.ts`.

Caveats stated in the UI: anyone with the link can read it; the link is the credential and will sit
in the recipient's chat history long after it stops working; and it cannot be re-issued, because the
half after the `#` was never anywhere but that URL.

### TOTP as a stored credential

A seed lives inside `payload_ct` like any other field, and `resources/js/crypto/totp.ts` turns it
into the six digits a user would otherwise read off a phone. It is **not** a column, for the same
reason `type` is not: a table saying which rows carry one-time-password seeds would be a list of the
accounts worth attacking, handed over for free.

There are two TOTP implementations in the project and they are not redundant. `App\Support\Totp`
guards *authentication* — the server holds that seed and checks that code. This one guards nothing;
it is a credential the server has never seen. Moving it server-side would mean handing over a seed
worth exactly as much as the password beside it.

HMAC-SHA1 by specification rather than by choice: SHA-1's collision weaknesses do not apply to HMAC,
and every authenticator expects it. SHA-256 and SHA-512 are accepted because `otpauth://` permits
them. Verified against RFC 6238's own appendix B vectors for all three hashes, which is the
reference worth matching — agreement between two implementations written from the same
misunderstanding proves nothing.

**There is no camera scanner.** `Permissions-Policy` denies `camera=()` outright, lifting that would
weaken a header that currently denies everything, and a QR decoder is another dependency for a path
that ends at the same string the paste field already accepts. Pasting the `otpauth://` URI — which
is what the QR code encodes, and what every setup page offers as "can't scan?" text — reaches the
same place.

### Audit chain (D9)

```
entry.hash = BLAKE2b-256( prev_hash ‖ canonical(entry) )

canonical(entry) = "vault.audit.v1" ‖ 0x00 ‖ seq ‖ 0x00 ‖ at ‖ 0x00 ‖ actor ‖ 0x00 ‖ action
                   ‖ 0x00 ‖ subjectType ‖ 0x00 ‖ subjectUuid ‖ 0x00 ‖ metadata
                   ‖ 0x00 ‖ signature ‖ 0x00 ‖ signedPayload ‖ 0x00 ‖ ipHash ‖ 0x00 ‖ uaHash
```

**NUL-joined fields, not `canonical_json` as this document first specified.** JSON has encoder
flags, escaping choices and key ordering, and every one of them is a way for a future PHP upgrade
or a stray flag to change the bytes of a hash computed years earlier — a failure with no recovery,
because the whole log would then report as tampered. The NUL join has nothing to drift, and it is
the construction `crypto/aad.ts` already uses for the binding this project depends on most. It is
injective because no field can contain a NUL: the action is a closed enum, identifiers are UUIDs,
the hashes are base64, and `metadata` is JSON, which escapes a NUL rather than emitting one.

`metadata` is hashed **exactly as stored**, never decoded and re-encoded, which is why its column
is `text` rather than `json` — the same trap as `grant_payload` and `jsonb`.

`seq` is a gapless integer, allocated under a row lock on a single-row `audit_chain` table. Locking
the *last event* instead is racy for inserts: a blocked transaction rechecks the row it waited on
rather than the new maximum, so two writers compute the same next sequence. Genesis has `prev_hash`
= 32 zero bytes. `php artisan vault:audit-verify` walks the chain and reports the first divergent
`seq`. Insertion, deletion, reordering and modification all break it.

**Truncation from the end does not break it**, and that is worth stating plainly: what remains is a
perfectly valid shorter chain. The stored head catches it, and the daily anchor catches a head that
was rewritten too.

The server writes entries, so a compromised server can rewrite the whole chain and recompute every
hash after the change. The chain alone stops careless tampering, not deliberate tampering. Two
hardenings, both real and neither a solution:

- **Client-originated events carry an Ed25519 signature from the acting user's key**, which the
  server cannot forge. Two actions qualify — `vault.unlocked` and `secret.revealed` — because they
  are the only two the server does not witness for itself. The set is closed for the same reason
  `signGrant` takes a grant rather than bytes: it is a signing oracle, and its vocabulary is the
  complete list of things injected script can make that key say.

  ```
  signature = Ed25519( "vault:audit:v1" ‖ 0x00 ‖ payload )
  payload   = {"v":1,"action":…,"subjectUuid":…,"at":…}   // stored verbatim
  ```

  Domain-separated from `vault:grant:v1`, since both are signatures by one key. The payload is
  stored exactly as signed, so a future change to the format cannot invalidate signatures already
  issued — the same rule as `grant_payload`.

- **The chain head is anchored outside the database**, emailed to the operator daily by
  `vault:audit-anchor`. This is the only part a compromised server cannot defeat: it can rewrite
  every row and recompute every hash, and it cannot reach into yesterday's inbox. Its strength
  comes entirely from the anchor being *elsewhere* — an address the same server administers proves
  nothing.

## Key handling in memory

- All key material lives in a **dedicated crypto Web Worker**. The main thread holds opaque
  handles and sends `{op, itemId, ciphertext}` messages. Injected script on the main thread can
  request decryptions; it cannot read the User Key. That is a meaningful reduction in blast
  radius, not a solution to XSS.
- Never `localStorage`, `sessionStorage`, IndexedDB, cookies, or the Vue/Inertia page props. This
  holds by construction — no code in `resources/js` calls any of those storage APIs at all — but
  construction is not a test, and the E2E assertion that would make it one is still outstanding
  (SR7, Phase 11).
- Overwrite `Uint8Array`s with zeros after use. In a garbage-collected runtime this is
  best-effort and does not survive `structuredClone` or GC copying — do it anyway, and document
  that it is hygiene rather than a guarantee.
- Auto-lock: idle timeout (default 15 minutes, configurable), on `visibilitychange` if enabled,
  and on `pagehide`. Locking terminates the Worker, which is the most reliable erasure available.
- Clipboard copies clear after 30 seconds where the Clipboard API permits.

## Parameter upgrades

KDF parameters are per-user columns, not constants. When defaults are raised:

- On next successful login, the client detects `user.kdf_params < current_default`, and — while it
  still holds the password in the Worker — re-derives at the new parameters, re-wraps the User
  Key, and submits new salt, params and auth key in one transaction.
- Silent, no user action, no data re-encryption. The same mechanism serves an envelope version
  bump (`ver`/`alg`), re-wrapping lazily on write.

## Explicitly rejected

| Rejected | Why |
| --- | --- |
| Deriving keys directly from the password with no User Key | A password change would re-encrypt everything |
| Email as the KDF salt | Not random; correlates across services; breaks on email change |
| One key per vault with no item keys | Rotation becomes a full re-encryption, as in 2017 |
| Server-side decryption "just for search" | Voids D1 outright |
| AES-256-CBC + HMAC (the 2017 primitive) | Encrypt-then-MAC done by hand, no AEAD, no AAD |
| Storing the recovery code server-side "to help users" | Voids D1 and D3 |
| `unsafe-inline` in the CSP for convenience | Voids the primary XSS control (D10) |
| Silently catching decrypt failures | The 2017 bug; violates SR3 |
