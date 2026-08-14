# 03 — Cryptographic Design

The specification. Phase 2 implements exactly this and nothing else; if reality forces a change,
this document changes first.

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

Pure-JS Argon2id at 64 MiB / t=3 is slow — plausibly 1–3 seconds on a laptop and worse on a
phone. Mitigations, in order:

1. Run all KDF work in a **Web Worker**, so the UI stays responsive and shows real progress.
   This is needed anyway for key isolation (see [Key handling in memory](#key-handling-in-memory)).
2. Benchmark on real devices as the first task of Phase 2, against a documented budget:
   **under 2 s on a modern laptop, under 5 s on a mid-range phone.**
3. If the budget is missed, swap the Argon2 implementation for `hash-wasm` behind the same
   interface. This costs `'wasm-unsafe-eval'` in `script-src`, which weakens D10's CSP. **That
   trade — a slower unlock versus a looser CSP — is a decision to make with measurements in hand,
   and to record as an ADR.** Do not pre-empt it.

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

Stored as `BLOB`/`BYTEA`. `ver` allows the envelope structure to change; `alg` allows the
primitive to change. A decryptor rejects anything it does not recognise with a specific error —
never a silent fallback.

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

Same as login, but step 2 uses `HKDF(recoveryCode, recoverySalt)` to unwrap the User Key.
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
4. `grant = { vault_uuid, recipient_uuid, recipient_fingerprint, role, key_epoch, granted_at }`;
   `signature = Ed25519_sign(granter.sk, canonical_json(grant))`.
5. POST the wrapped key, the grant and the signature.
6. The recipient's client **verifies the signature against the granter's pinned public key**
   before trusting the vault. A server-fabricated membership row has no valid signature.

The sealed box is: ephemeral X25519 keypair → `ECDH(eph_sk, recipient_pk)` →
`HKDF-SHA256(shared ‖ eph_pk ‖ recipient_pk, info="vault:seal:v1")` → XChaCha20-Poly1305.
Stored as `eph_pk ‖ envelope`. Anonymous to the recipient by construction, which is why the
separate signed grant carries the sender's identity.

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

### Files

Chunked AES-256-GCM via WebCrypto:

- `fileKey` ← 32 random bytes, wrapped by the Vault Key like any other item key.
- Chunk size 1 MiB. `nonce = noncePrefix(8 random bytes, per file) ‖ counter(4 bytes BE)`.
- Per-chunk AAD: `aad("file.chunk", file_uuid, v) ‖ chunk_index ‖ total_chunks ‖ is_final`.
  Binding the index and total is what prevents **truncation and reordering** — an attacker who
  drops the last chunk must otherwise be detected by the application, and here it is detected by
  the tag.
- A manifest (chunk count, chunk size, original size, SHA-256 of the plaintext) goes in the
  encrypted payload, not in a column.
- Filenames live in `payload_ct`. Object storage keys are random UUIDs with no extension.
- Upload: encrypt chunk-by-chunk in the Worker, stream to a presigned URL or a chunked endpoint.
- Download v1: fetch, decrypt to a `Blob`, hand to the browser. **Cap at ~100 MiB** — a Blob is
  memory-resident. Streaming download via a Service Worker + `TransformStream` is Phase 6's
  stretch goal and lifts the cap.

### One-time share links (D9)

The recipient has no account and no keys, so the link itself carries the key:

1. `linkKey` ← 32 random bytes. `token` ← 32 random bytes.
2. Client re-encrypts *just that secret's payload* under `linkKey` — this is why per-item keys
   matter; the Vault Key is never involved in the share.
3. POST `{ token_hash: BLAKE2b(token), payload_ct, expires_at, max_views }`. The server never
   receives `token` or `linkKey`.
4. The URL is `https://host/s/{token}#{base64url(linkKey)}`. **The fragment is never sent to the
   server** — that is the whole trick, and it is worth a comment in the code saying so.
5. On open, the page fetches by `token`, decrypts with the fragment key, and the server
   decrements the view count and deletes the record when exhausted or expired.

Caveats to state in the UI: anyone with the link can read it once; the link will sit in the
recipient's browser history and possibly their chat client's link preview fetcher, which may burn
the single view. Offer a view count above one for that reason.

### Audit chain (D9, Phase 7)

```
entry.hash = BLAKE2b-256( prev_hash ‖ canonical_json({seq, actor, action, subject, meta, at}) )
```

`seq` is a gapless integer, allocated under a row lock. Genesis entry has `prev_hash` = 32 zero
bytes. An artisan command walks the chain and reports the first divergent `seq`. Insertion,
deletion, reordering and modification all break it.

The server writes entries, so a compromised server can rewrite the whole chain. Two hardenings:

- Client-originated events (grants, revocations, rotations) carry an **Ed25519 signature from the
  acting user's key**, which the server cannot forge.
- The chain head is periodically anchored outside the database — emailed to the operator daily,
  or appended to an external append-only log. A rewritten chain then contradicts an anchor.

## Key handling in memory

- All key material lives in a **dedicated crypto Web Worker**. The main thread holds opaque
  handles and sends `{op, itemId, ciphertext}` messages. Injected script on the main thread can
  request decryptions; it cannot read the User Key. That is a meaningful reduction in blast
  radius, not a solution to XSS.
- Never `localStorage`, `sessionStorage`, IndexedDB, cookies, or the Vue/Inertia page props.
  Asserted in E2E tests (SR7).
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
