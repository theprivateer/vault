# 01 — Brief & Decisions

## Origin

The 2017 app (`../vault-2017`, Laravel 5.3) established a structure worth keeping:

```
User ──owns──> Vault ──> Lockbox ──> Secret
                            └──────> File
```

- `vaults` — owner, name, description, plus a `control` text column (an encrypted canary used to
  check the current key still decrypts) and a `user_vault` pivot carrying a `read_only` boolean.
- `lockboxes` — belong to a vault; name, description, notes.
- `secrets` — belong to a lockbox; encrypted `key` and `value`, a `linked_lockbox_id` (a secret
  whose value points at another lockbox), a `paranoid` flag, and `sort_order`.
- `files` — belong to a lockbox; stored on S3 via Flysystem, metadata in plaintext.

Encryption was two helper functions, `lock()` / `unlock()`, wrapping `Illuminate\Encryption\Encrypter`
with a single app-wide `VAULT_KEY` from `.env`. The `vault:key` command rotated it by looping every
row, decrypting with the old key and re-encrypting with the new one, then rewriting `.env`.

**What was wrong with it,** stated plainly, because the rebuild is defined by these:

1. One key for every secret of every user. Compromise of `.env` is total compromise.
2. The server decrypts. Anyone with server access — an attacker, a backup, a `dd()` left in a
   controller, an APM trace, an exception report — sees plaintext.
3. Only `key` and `value` were encrypted. Vault names, lockbox names, notes and filenames were
   plaintext, and names leak most of the value ("AWS root — production").
4. Rotation was a single-transaction-less loop with no resumability, no verification, and it
   rewrote `.env` by string replacement. A crash mid-run leaves a mixed-key database.
5. `getKeyAttribute()` swallowed `DecryptException` and returned `null` — integrity failures were
   silently indistinguishable from empty values.
6. AES-256-CBC + HMAC via the framework encrypter is fine, but there was no associated data, so
   ciphertexts were interchangeable between rows and fields.

## Goals

**Primary — this is a learning project.** The point is to build and understand a real
zero-knowledge system, including the parts that are genuinely hard: sharing without a trusted
server, revocation, rotation, recovery, and the limits of browser-delivered cryptography.

1. Correct, modern, well-documented cryptography with an explicit threat model.
2. Client-side encryption and decryption; the server is a dumb, untrusted blob store with
   authorisation.
3. Security engineering practice throughout: least privilege, defence in depth, tamper-evidence,
   secure defaults, honest documentation of what is *not* protected.
4. A dynamic, pleasant frontend that makes the crypto invisible in normal use.

**Non-goals.** Not a product. No billing, no orgs, no mobile app, no browser extension, no
enterprise SSO, no compliance certification. Not a drop-in 1Password replacement.

## Decisions

Settled up front. Each is load-bearing; changing one changes the phases downstream.

### D1 — True zero-knowledge end-to-end encryption

The server stores ciphertext and wrapped keys only, and holds no key that can decrypt user
content. No escrow, no server-side decryption path, ever.

*Why:* it is the only model where "the database leaked" and "the server was compromised at rest"
are survivable events, and it is the model with the most to learn from. Every subsequent
difficulty in this plan — sharing, search, recovery, rotation — is downstream of this choice, and
that is the point.

### D2 — Browser is the only client

No CLI, no CI agent, no machine identities, no server-side rendering of secret content. The web
client is the sole consumer of plaintext.

*Why:* keeps the zero-knowledge property intact with no exceptions to reason about. A machine
identity would be a legitimate design (a keypair like any other member), but it is deferred —
see [Deferred](#deferred).

### D3 — Recovery kit, and honest data loss

A one-time 128-bit recovery code is generated at signup and displayed once as a printable
emergency kit. The User Key is wrapped independently by the password KEK and the recovery KEK.
Lose both, and the data is gone — permanently, with no support path.

*Why:* the only recovery mechanism compatible with D1. The UI must say this in words, at signup,
and require an explicit acknowledgement.

### D4 — Split-key authentication

One password, two independent derivations. `Argon2id(password, salt)` produces 64 bytes: the
first 32 are the key-encryption key and never leave the browser; the second 32 are the auth key,
sent over TLS, and the server stores only a slow hash of it.

*Why:* well-understood, implementable with audited libraries, and no exotic dependencies. OPAQUE
would be stronger against a malicious server, but there is no mature PHP implementation and the
marginal gain is small next to the code-delivery problem (D10), which dominates.

### D5 — All metadata encrypted; search happens client-side

Vault names, lockbox names, descriptions, notes, secret keys, secret values, secret *types* and
filenames are all ciphertext. The server sees UUIDs, foreign keys, timestamps, sizes and sort
order. No blind indexes in v1. The client decrypts a vault on unlock and builds an in-memory
search index.

*Why:* names leak most of the information. The cost is real — no server-side sort, filter,
pagination or search — and accepting that cost consciously is more instructive than designing
around it. Blind indexes stay available as a later option if a vault ever outgrows memory.

### D6 — Item content is one encrypted JSON payload

Rather than a ciphertext column per field, each vault, lockbox, secret and file stores a single
`payload_ct` blob containing all of its user-visible fields as JSON.

*Why:* fewer columns, less structural leakage (the server cannot tell a TOTP seed from a note),
schema changes become payload-version changes rather than migrations, and there is exactly one
place per record where AAD binding must be correct.

### D7 — Per-item keys under a per-vault key

Each vault has a random Vault Key. Each item has its own random Item Key, wrapped by the Vault
Key and stored alongside the item.

*Why:* three payoffs. Revoking a member requires re-wrapping N 32-byte item keys, not
re-encrypting N payloads. A single secret can be shared (D9's one-time links) without exposing
the Vault Key. And the blast radius of any one key is one item.

### D8 — Sharing by direct grant to verified public keys

You can only share with a user who already has an account and a published keypair. The owner's
browser fetches the recipient's public key, displays its fingerprint for out-of-band
verification, seals the Vault Key to it, and signs the grant with its Ed25519 key. Clients pin
keys they have seen (TOFU) and warn loudly on change.

Roles are Owner / Editor / Viewer, enforced by server-side policies. **Read-only is not
cryptographically enforceable** — anyone who can decrypt can copy — and the UI must say so.

### D9 — Scope beyond 2017 parity

In, sequenced into later phases:

- Tamper-evident hash-chained audit log
- Secret version history and rollback
- TOTP code generation and password/passphrase generators
- One-time self-destructing share links

### D10 — Strict CSP, SRI, and a written threat model

Nonce-based strict CSP with `strict-dynamic`, no inline script, no `eval`, Trusted Types,
subresource integrity on bundles, and a document that states plainly that a malicious or
compromised server can serve JavaScript that exfiltrates the master key. Reproducible builds and
edge verification are noted as future work, not built.

### D11 — Self-hosted, small trusted group

One instance. Users own vaults directly and share peer-to-peer. No organisation layer, no tenant
column, no admin who can read your data. Registration is invite-only, bootstrapped by an artisan
command.

### D12 — Greenfield

No import from the 2017 database. Anything worth keeping gets copied across by hand. This avoids
building an import path that would necessarily handle plaintext server-side and undermine D1 on
day one.

## Deferred

Recorded so they are choices rather than oversights. Each is a plausible later phase.

| Item | Why deferred | What it would need |
| --- | --- | --- |
| Passkey (WebAuthn PRF) unlock | Authenticator support for the PRF extension is uneven | A third wrapping of the User Key; a fallback path for non-PRF authenticators |
| Machine identities / CLI | D2 | A keypair per machine, added as a vault member; a token auth path |
| Blind indexes | D5 — not needed at this scale | HMAC index columns, careful analysis of equality-pattern leakage |
| Organisations, admin escrow | D11 | An org layer and a re-answer to "who can read your data" |
| Reproducible builds, edge verification | D10 — research-grade | Deterministic Vite builds, signed manifests, an extension or verifier |
| Import from 1Password/Bitwarden/CSV | D12 | A client-side parser and importer; also gives an export path |
| Secret expiry and rotation reminders | Not requested | A due-date field in the payload; client-side surfacing |
| Breach checking (HIBP k-anonymity) | Not requested | Client-side SHA-1 prefix queries; a CSP `connect-src` exception |

## A note on what "read-only" means

Worth stating once, prominently, because it recurs: in any end-to-end encrypted system, the
ability to decrypt is the ability to read, and the ability to read is the ability to copy.
Server-side role enforcement stops a Viewer from *writing through the API*. It does not and
cannot stop them from saving what they have already decrypted. The audit log (Phase 7) is the
compensating control, and honest UI copy is the rest.
