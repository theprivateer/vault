# Vault — Design & Implementation Plan

A ground-up rebuild of the 2017 Vault app as a **zero-knowledge, end-to-end encrypted** secret manager.

The 2017 app encrypted secrets at rest with a single application-wide key and decrypted them
on the server before rendering. This rebuild moves the trust boundary: **the server stores
ciphertext and wrapped keys, and never holds a key capable of decrypting them.**

## Read in this order

| Doc | What it covers |
| --- | --- |
| [01 — Brief & Decisions](01-brief-and-decisions.md) | Goals, scope, the twelve settled decisions and their rationale |
| [02 — Threat Model](02-threat-model.md) | Assets, adversaries, what is and is not protected, accepted risks |
| [03 — Cryptographic Design](03-cryptographic-design.md) | Key hierarchy, primitives, envelope format, every protocol flow |
| [04 — Data Model](04-data-model.md) | Schema, what each column leaks, migration notes |
| [05 — Implementation Plan](05-implementation-plan.md) | **The phases.** 13 phases, each with deliverables and exit criteria |
| [06 — Testing & CI](06-testing-and-ci.md) | Test strategy, the leak canary, CI gates |
| [adr/](adr/) | Decision records — why a choice was made, and what was rejected |

## The one-paragraph summary

A user's password is stretched with Argon2id in the browser into two independent keys: a
key-encryption key that never leaves the device, and an auth key that is all the server ever
sees. The KEK unwraps a random per-account **User Key**, which in turn unwraps the user's
X25519 and Ed25519 private keys. Each vault has a random **Vault Key**, sealed individually to
each member's X25519 public key. Each item (secret, lockbox, file) has its own **Item Key**
wrapped by the Vault Key, so revocation and rotation cost a re-wrap of 32-byte blobs rather
than a re-encryption of all content. Every ciphertext is bound by AEAD associated data to the
record it belongs to, so a malicious server cannot move a ciphertext from one field or row to
another. Item content is a single encrypted JSON payload, so names, notes and types are all
opaque to the server; search happens in the browser.

## Stack

- **Backend** — Laravel 13, PHP 8.4 (`ext-sodium` built in), Pest 5
- **Frontend** — Inertia v3 + Vue 3 + TypeScript (strict), Tailwind 4, Vite 8
- **Crypto** — `@noble/ciphers`, `@noble/curves`, `@noble/hashes` in the browser; WebCrypto for
  RNG and for bulk file encryption (AES-256-GCM, the one hardware-accelerated exception —
  [03 § Files](03-cryptographic-design.md#files)). Nothing on the server.

## Status

**Phases 0 to 9 complete.**

- **Phase 0** — Inertia v3 + Vue 3 + TypeScript strict, a strict nonce-based CSP enforced from
  the first render, Larastan at max level, and CI gating every check.
- **Phase 1** — the crypto core in `resources/js/crypto`: envelope format with mandatory AAD
  binding, the key hierarchy, sealed boxes, identities, and the crypto Worker. Held at 100% branch
  coverage ever since, verified against RFC vectors and cross-checked byte-for-byte against PHP's
  `ext-sodium`. Argon2id measured at 731 ms, so the CSP stays free of `wasm-unsafe-eval`
  ([ADR-0003](adr/0003-argon2id-implementation.md)).

- **Phase 2** — identity, unlock and recovery. Invite-only registration, split-key login, the
  recovery kit, password change, TOTP second factor, and the unlock state machine. Monochrome
  monospace interface with `rounded-*` and `shadow-*` removed at the token level.

- **Phase 3** — vaults, lockboxes and secrets, end to end. Every name, value and note is encrypted
  in the browser under a per-item key, and `sqlite3 .dump` returns nothing but noise
  ([06](06-testing-and-ci.md#verified-by-hand-once)). The leak canary, the IDOR suite and the
  no-server-decryption gate all run on every commit.

- **Phase 4** — the decrypted-item store and its synchronous wipe on lock, bulk decryption in the
  Worker, client-side search, payload padding, and optimistic writes with concurrent-edit
  detection. The scale ceiling is
  [measured rather than asserted](06-testing-and-ci.md#the-scale-ceiling-measured).

- **Phase 5** — sharing by signed grant, trust-on-first-use fingerprint pinning with a hard stop
  when a key changes, and revocation that triggers an atomic re-key at exactly `key_epoch + 1`.
  The phase where the asymmetric layer earns its place.

- **Phase 6** — encrypted file attachments: chunked AES-256-GCM through WebCrypto, with each
  chunk's index and its file's chunk count bound into the AAD, so truncation and reordering fail
  the tag rather than an application check. Resumable uploads, per-vault quotas, an orphan sweep,
  and filenames that exist only inside the encrypted manifest. Capped at 100 MiB pending the
  [streaming download](05-implementation-plan.md#carried-forward-from-phase-6).

- **Phase 7** — the tamper-evident audit log: a BLAKE2b chain over every action, with `seq` gapless
  under a row lock, append-only enforced three ways, and `vault:audit-verify` naming the first
  entry that diverges. The two events the server cannot witness — a vault unlocked, a secret
  revealed — are reported by the browser and **signed**, so the one thing a compromised server
  could invent is the one thing it cannot. The chain head is mailed to the operator daily, because
  a server that can recompute every hash still cannot reach yesterday's inbox.

- **Phase 8** — version history: an edit appends rather than overwrites, and the archived payload is
  a *fresh encryption* bound to its own identity rather than a copy of the column it replaced —
  which is what stops a server writing an old password back over the current one. Diffing is
  client-side because the server cannot compare two ciphertexts under two keys. Restoring is an
  ordinary edit carrying old plaintext, so it is never destructive by construction. Retention bounds
  the liability and a purge ends it outright, because history of a credential rotated *because it
  leaked* is a copy of the leaked credential kept somewhere convenient.

- **Phase 9** — the features that make it a tool you would use: TOTP codes generated in the browser
  from a seed the server has never seen, password and passphrase generators whose entropy figure is
  arithmetic rather than an estimate, and one-time share links for people with no account. The link
  carries its own key in the URL fragment, so the server stores a blob it cannot read and a hash it
  cannot reverse — and because the token is in the fragment too, a chat client's link preview cannot
  spend the single view.

Next: [Phase 10 — key lifecycle at scale](05-implementation-plan.md#phase-10--key-lifecycle-at-scale).
