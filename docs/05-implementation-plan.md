# 05 — Implementation Plan

Thirteen phases. Each has a single theme, produces something demonstrable, and ends with exit
criteria that are checkable rather than felt. Nothing in phase N depends on phase N+1.

Sizes are relative effort, not dates: **S** ≈ a sitting, **M** ≈ a few, **L** ≈ a sustained
stretch, **XL** ≈ the biggest things here.

## Dependency graph

```
0 Foundations
└─> 1 Crypto core ─────────────────────────────┐
    └─> 2 Identity & unlock                    │
        └─> 3 Vault CRUD + leak canary         │
            ├─> 4 Client state & search        │
            │   └─> 5 Sharing & revocation     │
            │       ├─> 6 Files                │
            │       ├─> 7 Audit log            │
            │       ├─> 8 Version history      │
            │       └─> 9 TOTP / links         │
            │           └─> 10 Key lifecycle   │
            └───────────────────────────────────┴─> 11 Hardening ─> 12 Ops & release
```

Phases 6–9 are independent of one another and can be reordered or dropped freely. Everything
through phase 5 is load-bearing.

**If you build only three:** 1, 2, 3. That is a working single-user zero-knowledge vault, and it
contains most of the learning.

---

## Phase 0 — Foundations & guardrails

**Size: M.** Set the constraints before writing code that would violate them. Retrofitting a
strict CSP or a type-checked codebase is far more expensive than starting with one.

### Deliverables

- Inertia v3 + Vue 3 + TypeScript (strict) on the existing Laravel 13 skeleton.
- CI that fails the build on any quality or security gate.
- Architecture Decision Records, and `.ai/rules` seeded so future agent sessions inherit the
  constraints rather than rediscovering them.
- **A strict CSP in place from the first page render.**

### Tasks

1. Install the Laravel starter kit (Inertia + Vue). Confirm versions rather than assuming:
   `inertiajs/inertia-laravel` v3.x and `@inertiajs/vue3` v3.x are current.
2. TypeScript with `strict: true`, `noUncheckedIndexedAccess: true`. `tsc --noEmit` in CI.
   `noUncheckedIndexedAccess` matters here specifically — this codebase indexes byte arrays
   constantly.
3. Backend quality: Pint, Larastan at max level, `composer audit`.
4. Frontend quality: ESLint, Prettier, `npm audit`, Vitest.
5. Pest 5 configured with coverage; a **minimum coverage gate on `resources/js/crypto/**` of
   100%**, and a lower bar elsewhere. Total coverage numbers are noise; coverage of the crypto
   module is not.
6. **Security headers middleware**, applied globally from day one: nonce-based CSP with
   `strict-dynamic`, `object-src 'none'`, `base-uri 'none'`, `frame-ancestors 'none'`,
   `connect-src 'self'`, HSTS, `X-Content-Type-Options`, `Referrer-Policy: no-referrer`,
   a restrictive `Permissions-Policy`, and COOP/CORP.
   Vite's dev server needs a relaxed variant — keep it in a clearly-marked `local`-only branch
   so it can never ship.
7. `SESSION_ENCRYPT=true`, `SameSite=Strict`, `Secure`.
8. Disable or scrub anything that could capture secret material in a stack trace: exception
   reporting body scrubbing, `APP_DEBUG=false` outside local, no query logging in production.
9. ADR template in `docs/adr/`; write ADR-0001 recording D1–D12 as accepted.
10. `record-rule` entries for the rules that must survive into future sessions: *no server-side
    decryption*, *no plaintext in logs*, *AAD on every seal*, *decrypt throws, never returns null*.

### Exit criteria

- `composer test`, `npm run test`, `tsc --noEmit`, Pint, Larastan and both audits pass in CI.
- A page renders through Inertia with the strict CSP active and **zero console violations**.
- Attempting to add an inline `<script>` fails at runtime — verified deliberately, once.

### Risks

Tailwind 4 and Vite 8 with a nonce-based CSP need `style-src` handled carefully; Vite injects
styles at dev time. Resolve it now rather than discovering it in phase 11.

---

## Phase 1 — Crypto core library

**Size: XL. The most important phase.** A standalone, framework-free, exhaustively tested
TypeScript module. It must not import Vue, Inertia, or anything from the app. It is the thing
worth getting right; everything else is CRUD around it.

### Deliverables

`resources/js/crypto/` exporting a small, hard-to-misuse API, with 100% branch coverage and
known-answer tests.

```
crypto/
  primitives.ts    argon2id, hkdf, blake2b, randomBytes, constantTimeEqual
  envelope.ts      seal() / open(), version+alg header, AAD construction
  aad.ts           canonical AAD building — one place, tested hard
  keys.ts          deriveFromPassword, generateUserKey, wrap/unwrap, sealTo/openSealed
  identity.ts      keypair generation, self-signing, fingerprints
  errors.ts        IntegrityError, UnsupportedEnvelopeError, KeyUnavailableError
  worker/          the crypto Worker and its typed message protocol
  index.ts
```

### Tasks

1. **Benchmark Argon2id first**, before anything is built on it. Real devices, documented
   numbers, against the budget in [03 § KDF performance](03-cryptographic-design.md#kdf-performance).
   If `@noble/hashes` misses it, decide `hash-wasm` versus the CSP cost **now** and record an ADR.
   This is a fork in the road; do not discover it in phase 2.
2. Implement the envelope format exactly as specified. `seal()` **requires** an AAD argument —
   make it a required positional parameter with no default, so forgetting it is a type error
   rather than a silent security hole.
3. Implement the sealed box (ephemeral X25519 → HKDF → XChaCha20-Poly1305).
4. Build the crypto Worker with a typed request/response protocol. Key material enters the
   Worker and never leaves. The main-thread API returns handles.
5. Zeroisation helpers, with a comment stating honestly that they are best-effort in a GC'd
   runtime.
6. Testing, which is the bulk of the phase:
   - **Known-answer tests** against RFC 8439 (ChaCha20-Poly1305), RFC 7748 (X25519),
     RFC 8032 (Ed25519), RFC 9106 (Argon2id), RFC 5869 (HKDF). Vectors committed as fixtures.
   - Round-trip property tests across random sizes including 0 and 1 byte.
   - **Tamper tests:** flip every bit position in a short envelope; each must throw
     `IntegrityError`. Truncate; extend; swap nonces.
   - **AAD binding tests:** seal under record A's AAD, attempt to open as record B, assert
     failure. This is SR4 and it deserves its own test file.
   - Unknown `ver`/`alg` rejection.
   - Cross-check a sample of outputs against PHP's `ext-sodium` in a Pest test, to catch an
     encoding or endianness mistake that agrees with itself in JS.
7. Document every exported function with the AAD context it expects.

### Exit criteria

- All KATs pass; 100% branch coverage on the module.
- Every single-bit mutation of a test envelope throws.
- No `catch` block in the module swallows an error.
- The module builds and tests standalone with zero app imports (enforced by an ESLint
  `no-restricted-imports` rule).
- The Argon2id benchmark is written down in an ADR with the decision it drove.

---

## Phase 2 — Identity, unlock & recovery

**Size: L.** The full account lifecycle with no vaults yet. At the end, a user can register,
log in, unlock, lock, change their password and recover — and the server still holds nothing that
can decrypt anything.

### Deliverables

Registration, login, unlock/lock state machine, recovery kit, password change, TOTP second
factor, invite-only onboarding.

### Tasks

1. Migrations: `users`, `user_key_wraps`, `user_identities`, `invites`.
2. `php artisan vault:invite {email}` to bootstrap the first account, since registration is
   closed.
3. Registration flow per [03 § Registration](03-cryptographic-design.md#registration). All crypto
   in the Worker; the server receives blobs and a public key bundle.
4. **The recovery kit screen** — displayed once, print stylesheet, copy button, mandatory
   acknowledgement checkbox with the data-loss wording spelled out.
5. `POST /auth/kdf-params` with the **deterministic decoy salt** for unknown accounts. Write the
   enumeration test alongside the endpoint: unknown email and known email must return
   the same shape, and their timings must not diverge meaningfully.
6. Login: verify `authKey` with `Hash::check` (argon2id driver), return the wrapped User Key
   bundle. Rate limit per IP **and** per account; exponential backoff; generic errors throughout.
7. TOTP second factor: `user_totp`, enrolment with QR, backup codes stored hashed. Note clearly
   in code and docs that this protects *authentication only* — it cannot gate decryption, because
   decryption doesn't involve the server.
8. **The unlock state machine**, as a first-class Vue store: `anonymous → authenticated → unlocked
   → locked`. Idle timer, `visibilitychange` and `pagehide` handlers, Worker termination on lock.
9. Recovery flow, forced password change on success, fresh kit issued, high-severity log line and
   email notification.
10. Password change with fresh salt, re-wrap, atomic submit.
11. Replace the password-reset routes with a page explaining why there is no reset.

### Exit criteria

- Register → log out → log in → unlock works end to end.
- Recovery unlocks an account whose password is genuinely unknown to the tester.
- Password change does not alter `user_identities` ciphertexts (assert the bytes are byte-identical
  before and after — the visible proof that the User Key indirection works).
- Enumeration test passes for unknown, known and malformed emails.
- **SR7 test:** after unlock, `localStorage`, `sessionStorage`, IndexedDB and cookies contain no
  key material. Write this test now; it guards every later phase.
- Throttling tests: N failed logins lock the account and the IP.

---

## Phase 3 — Vaults, lockboxes, secrets

**Size: L.** 2017 feature parity for a single user, done properly. This is the phase where the
whole thesis becomes real.

### Deliverables

E2EE CRUD for vaults, lockboxes and secrets, and **the leak canary** that keeps it honest.

### Tasks

1. Migrations for `vaults`, `vault_memberships`, `lockboxes`, `secrets` per [04](04-data-model.md).
2. Models with a **`Ciphertext` cast** that exposes the blob as an opaque value object. The cast
   must have no `decrypt()` path — the compile-time-ish guarantee that no controller can
   accidentally reach through it. This is the direct answer to 2017's `getKeyAttribute()`.
3. Client-side UUIDv7 generation; server-side validation of version and uniqueness.
4. Form requests validating **shape and size only**: is it a blob, is it under the size cap, is
   the version byte recognised. Nothing may parse a payload.
5. Policies for every model. Every read and write checks `vault_memberships`. Never trust a
   `vault_id` from the request — resolve it from the resource.
6. Vue: vault list, lockbox list, secret detail, create/edit forms. Encryption happens in the
   Worker before the request is built, so the network layer only ever sees ciphertext.
7. Reveal/copy/hide interactions, `paranoid` re-auth prompt, clipboard auto-clear.
8. `linked_lockbox_id` — the 2017 lockbox-as-a-value feature, with same-vault enforcement.
9. **The leak canary (SR1).** A Pest test that:
   - creates a secret whose value is a unique random sentinel string,
   - then greps the entire database, every log file, the cache store, the queue tables and the
     storage disk for that sentinel,
   - and fails loudly if it appears anywhere.
   Run it in CI on every commit. It is the single highest-value test in the project, and it will
   catch a mistake that code review will not.
10. A CI grep gate asserting no `decrypt`, `Crypt::`, `openssl_`, or `sodium_crypto_*_open` call
    exists in `app/` (SR2).

### Exit criteria

- Full CRUD works; the browser can read everything, and `sqlite3 database.sqlite .dump` reveals
  nothing but noise. **Do this by hand once and screenshot it** — it is the moment the project
  justifies itself.
- Leak canary passes.
- IDOR suite: user B receives 404 (not 403 — 403 confirms existence) on every one of user A's
  resources.
- Tampering with a `payload_ct` byte in the database produces a visible integrity error in the UI,
  not an empty field.

---

## Phase 4 — Client state, search & UX

**Size: M.** D5 says search is the client's problem. This is where that bill comes due.

### Deliverables

A decrypted in-memory model of the unlocked vault, fast search, and honest handling of scale.

### Tasks

1. A Pinia store holding decrypted items for the unlocked vault, subscribed to lock events so it
   is wiped synchronously on lock.
2. Bulk decrypt on vault open, in the Worker, batched with progress reporting. Measure it.
3. In-memory search index (a trigram or inverted index over names and usernames; `fuse.js` is
   acceptable if it earns its bundle size). Search runs against decrypted data and never touches
   the network — say so in the UI, because it is a genuinely nice property.
4. **Measure and document the scale ceiling.** Benchmark 100 / 1,000 / 10,000 secrets: decrypt
   time, memory, search latency. Write the numbers down. When someone later asks "why not blind
   indexes", the answer should be a measurement.
5. Optimistic updates with rollback on failure, and correct conflict handling on concurrent edit.
6. Payload **padding to bucket sizes** (e.g. next power of two up to 4 KiB) before encryption, to
   blunt the length side-channel from [02 § Accepted leakage](02-threat-model.md#accepted-leakage).
   Cheap, and it must happen before ciphertexts exist in quantity.
7. Keyboard-first navigation, command palette, empty and error states.
8. Accessibility pass: focus management on reveal, screen-reader labelling of masked fields, no
   colour-only status.

### Exit criteria

- A 1,000-secret vault opens in under two seconds on a laptop, with numbers recorded.
- Search is instant and demonstrably offline (works with DevTools set to offline).
- Locking wipes the store; a screenshot of the heap after lock shows no plaintext.
- Padding is applied and its effect on stored sizes is verified.

---

## Phase 5 — Sharing, membership & revocation

**Size: XL. The hardest phase, and the most interesting.** Everything before this is achievable
with symmetric crypto alone. This is where the asymmetric layer earns its place.

### Deliverables

Grant, accept, revoke — with fingerprint verification, signed grants and re-keying on revocation.

### Tasks

1. Public identity endpoint; self-signature verification client-side.
2. **The pin store** (`user_pin_stores`): encrypted TOFU cache of fingerprints. Warn on first
   sight; **hard-stop on change**, with a red interstitial and no one-click override.
3. Fingerprint rendering — six 4-character groups, plus a visual hash (an identicon derived from
   the fingerprint) because people compare pictures more reliably than hex.
4. Grant flow: seal the Vault Key, build the canonical grant, sign it, submit. Store the exact
   signed bytes in `grant_payload` so verification survives a future canonicalisation change.
5. Accept flow: the recipient's client **verifies the granter's signature against a pinned key**
   before the vault appears as trusted. An unverifiable grant renders as a warning, not a vault.
6. Role enforcement in policies: `viewer` blocked from every write path. Test each verb per role,
   exhaustively — a table-driven test with a row per (role × action).
7. **Revocation triggers re-key.** Server sets `revoked_at` and `rekey_required_at` atomically and
   cuts API access immediately. The owner's next unlock prompts a re-key: new Vault Key, all item
   keys re-wrapped, sealed to remaining members, submitted as **one atomic request** which the
   server accepts only at exactly `key_epoch + 1` with a complete item set. Partial re-keys are
   rejected, not half-applied — the explicit fix for 2017's resumability failure.
8. UI copy stating that revocation prevents future access and cannot retract past reads.
9. Ownership transfer, and the guard preventing deletion of a shared vault.

### Exit criteria

- Two accounts share a vault end to end, with fingerprint verification.
- A grant with a tampered signature is rejected by the recipient's client.
- Substituting a public key server-side produces the hard-stop interstitial (test this by actually
  editing the row).
- After revocation and re-key, the old member's cached Vault Key decrypts nothing new: assert that
  every item key is a different ciphertext and `key_epoch` advanced.
- A deliberately interrupted re-key leaves the vault fully on the old epoch, never mixed.

### Carried forward from Phase 5

Tasks 1–8 are built and every exit criterion above has a passing test. **Task 9 is not.** Ownership
transfer and the guard against deleting a shared vault are both still outstanding, and the two are
the same problem seen from either end: a vault with other members must have somewhere to go before
its owner can leave, or the members are left holding a Vault Key that wraps rows nobody can reach.
The deletion semantics in [04](04-data-model.md#cascade-and-deletion-semantics) already say the UI
blocks deletion until a transfer has happened; the UI does not yet block it.

What *is* in place is the narrower guard underneath: `VaultMembershipPolicy` refuses to revoke an
owner's membership, so the last administrator cannot be removed by the revocation path. Deleting
the vault outright is the route that is still open.

---

## Phase 6 — Encrypted file attachments

**Size: L.** Independent of 7–9.

### Tasks

1. `files` migration; chunked AES-GCM per [03 § Files](03-cryptographic-design.md#files).
2. Chunked upload with resumability, per-chunk AAD binding index and total.
3. Download v1: fetch → decrypt → Blob, capped at ~100 MiB with a clear message beyond it.
4. **Truncation and reorder tests** — drop the final chunk, swap two chunks, replay a chunk from
   another file. All must fail closed.
5. Orphan cleanup for uploads that never completed; hard-delete blobs when a file row is purged.
6. Image and text preview by decrypting to an object URL, revoked immediately after use.
7. Quotas per vault, enforced server-side on `ciphertext_size`.

### Exit criteria

Round-trip a 500 MiB file; byte-identical SHA-256. Tamper tests fail closed. No orphaned objects
after a delete-and-purge cycle. Object storage contains no filenames or extensions.

**Stretch:** streaming download via Service Worker + `TransformStream`, which removes the cap.

### Carried forward from Phase 6

Tasks 1–7 are built, and the tamper, orphan and object-storage criteria all have passing tests —
`resources/js/crypto/chunks.test.ts` for the cipher's own guarantees, `resources/js/lib/files.test.ts`
for the same attacks mounted by a dishonest server across a whole round trip, and
`tests/Feature/Vault/FileTest.php` for quotas, idempotency and the sweep. The leak canary gained a
file case, so a filename reaching a column, a log or a path fails the build.

**The 500 MiB round trip is not one of them.** This build caps a file at 100 MiB
(`vault.files.max_bytes`) because a download is reassembled in the browser, so the number in that
criterion belongs to the streaming stretch goal rather than to what is here. The round trip is
tested across many chunks at kilobyte sizes, which exercises every boundary the size would; what
is untested is the scale. Say that rather than quietly restating the criterion at a size that
passes.

**Also outstanding:** the streaming download itself, and parallel chunk uploads. Chunks go one at a
time, which is slower than the connection allows and was the right trade while the ordering and
resume story was being settled. Both are measurements away, not designs away.

---

## Phase 7 — Tamper-evident audit log

**Size: M.** Cheap to build, and the main compensating control for everything the server cannot
see.

### Tasks

1. `audit_events` with gapless `seq` under a row lock, and the BLAKE2b chain.
2. Append-only enforcement: no update route, no `updated_at`, and a production database grant that
   denies `UPDATE`/`DELETE` to the app role.
3. Event coverage: auth, unlock, secret view, every CRUD verb, grants, revocations, re-keys,
   recovery use, share links, file access.
4. Ed25519 `actor_signature` on client-originated events.
5. `php artisan vault:audit-verify` — walks the chain, reports the first divergent `seq`.
6. Daily head-hash anchoring: email the operator, so a rewritten chain contradicts an external
   record.
7. Vault activity UI, and a per-user "where am I signed in / what have I accessed" view.
8. **A metadata linter test** asserting no `metadata` key ever contains decrypted content — the
   obvious way this table becomes an accidental plaintext leak.

### Exit criteria

`vault:audit-verify` passes on a populated database, and detects a modified row, a deleted row and
a reordered row in three separate deliberate-corruption tests. Signatures verify.

### Carried forward from Phase 7

All eight tasks are built and every exit criterion has a passing test in
`tests/Feature/Vault/AuditChainTest.php` — plus two the criteria did not ask for: a chain truncated
from the *end*, and a rewritten head. Both matter, because neither is caught by the hash chain
itself. Signature behaviour is in `AuditSignatureTest.php`, including the case the whole signing
design exists for: an entry the server fabricated afterwards, with every hash recomputed so the
chain verifies perfectly and only the signature gives it away.

Three departures from what this plan and docs/03 originally specified, each with its reason
recorded where it is implemented:

- **The canonical form is NUL-joined fields, not `canonical_json`.** JSON has flags and encoders;
  a hash computed years earlier must not depend on any of them.
- **`seq` is allocated under a lock on a one-row `audit_chain` table**, not on the last event.
  Locking the last event is racy for inserts.
- **Only two actions are client-signed** — `vault.unlocked` and `secret.revealed` — rather than
  "grants, revocations, rotations". Those three are server-observed; taking the client's word for
  something the server watched happen adds nothing and widens a signing oracle.

**Outstanding:** the production `REVOKE UPDATE, DELETE` is documented in the migration and in
docs/04 but is not applied by anything here — it belongs to the deployment work in Phase 12, and
until then the append-only guarantee rests on the two layers that are code. Anchoring needs
`VAULT_AUDIT_ANCHOR_ADDRESS` set to an address the server does not administer, or it is not an
anchor; the command fails loudly rather than pretending otherwise.

---

## Phase 8 — Version history & rollback

**Size: M.**

### Tasks

1. `secret_versions`; writes append rather than overwrite, each version with its own Item Key.
2. Diff view — client-side, since the server cannot diff ciphertext.
3. Restore-as-new-version (never destructive).
4. **Retention policy**: last 20 versions / 180 days by default, configurable per vault, with an
   explicit purge action. Surface the tension in the UI: history is useful, and history of a
   password you rotated *because it leaked* is a liability.
5. Re-key must cover versions — extend phase 5's atomic re-key set to include version item keys.

### Exit criteria

Edit, view history, diff, restore. Retention prunes correctly. A re-key after history exists
re-wraps version keys too, and old versions still open afterwards.

### Carried forward from Phase 8

All five tasks are built and every exit criterion has a passing test —
`tests/Feature/Vault/HistoryTest.php` for appending, restoring, purging, retention and the sweep,
`tests/Feature/Vault/RekeyTest.php` for rotation covering version keys with payloads untouched, and
`resources/js/lib/history.test.ts` and `diff.test.ts` for the client half.

**One departure from the task list, and it is the reason the phase took the shape it did.** Task 1
said "writes append rather than overwrite, each version with its own Item Key", which reads as
though the server could copy the outgoing payload into the history table. It cannot, and it must
not: a copy carries associated data binding it to the live column, so any archived version could be
written back over the current row and would verify. The browser therefore re-seals the outgoing
plaintext under `secret.version.payload` at the version row's own UUID and posts it with the edit,
which is why `UpdateSecretRequest` requires four fields the old one did not.

**A Phase 6 bug fell out of task 5.** `VaultRekeyController::itemKeys()` covered lockboxes and
secrets only, so file attachments were never in the rotation set: a re-key would have reported
success and left every attachment in the vault permanently unopenable, its Item Key still wrapped
under a Vault Key the client had just discarded. Files and versions are both in the set now, and
`RekeyTest` refuses an incomplete submission that omits either.

**Outstanding:** nothing from this phase's own list. The interaction worth watching is that a vault
with deep history and many secrets makes a re-key a much larger submission — 20 versions per secret
is 20× the wrapped keys — and the scale ceiling measured in
[06](06-testing-and-ci.md#the-scale-ceiling-measured) predates that.

---

## Phase 9 — TOTP, generators & one-time links

**Size: M.** The features that make it a tool you would actually use.

### Tasks

1. TOTP seeds stored inside `payload_ct` (RFC 6238), codes generated client-side with a countdown
   ring. `otpauth://` URI import, and QR scanning via camera if the CSP allows it cleanly.
2. Password generator (length, character classes) and passphrase generator (EFF wordlist, bundled
   locally — no CDN, which the CSP forbids anyway). Entropy shown in bits.
3. Strength estimation with `zxcvbn-ts`, entirely client-side.
4. One-time share links per [03](03-cryptographic-design.md#one-time-share-links-d9): link key in the
   URL fragment, `token_hash` server-side, view counting, expiry, a scheduled purge job.
5. The recipient view for someone with no account, on a page with the same strict CSP.
6. UI caveats: link previews in chat clients can consume a view; offer a view count above one.

### Exit criteria

TOTP codes match a reference authenticator for a known seed. A share link opens exactly once and
then 404s. The server logs, across the whole flow, contain neither the token nor the fragment —
assert this, since it is the entire security argument for the design.

### Carried forward from Phase 9

All six tasks are built and every exit criterion has a passing test. TOTP is checked against
RFC 6238's own appendix B vectors for SHA-1, SHA-256 and SHA-512 rather than against another
implementation; `tests/Feature/Vault/ShareLinkTest.php` opens a link, opens it again, gets a 404,
and then sweeps every table and every log file for both halves of the credential.

**Three departures, each recorded where it is implemented.**

The token moved out of the URL path and into the fragment. `/s/{token}` cannot satisfy the log
requirement — a path segment is written to every reverse-proxy access log in the clear, and no
application-level control changes that. Both halves now live in the fragment and the token arrives
in a request body. This also removes task 6's caveat entirely: an unfurler fetching `GET /s` never
sees a token, so **a link preview cannot burn a view**. `max_views` above one remains, for the
recipient who reloads or opens it on a second device.

`zxcvbn-ts` was declined and a smaller in-house estimator written instead — three packages and
several hundred kilobytes of dictionaries against a threat model that names a small dependency
surface as a defence (A10). The cost is real: it has no dictionary and will overrate a word or a
name, so the meter says exactly that on screen, and `strength.test.ts` pins the limitation as a
property rather than leaving it to be rediscovered as a bug.

**There is no camera QR scanner**, which task 1 made conditional on the CSP allowing it cleanly. It
does not: `Permissions-Policy` denies `camera=()` outright, lifting that would weaken a header that
currently denies everything, and a QR decoder is another dependency for a path that ends at the same
string the paste field already takes. Pasting the `otpauth://` URI is what a QR code encodes anyway.

**Outstanding:** nothing from this phase's own list.

`/account/links` lists every link the current user can withdraw, and its contents are derived from
the same rule as the revoke ability rather than beside it — your own links, plus any issued into a
vault you administer. That equivalence is the point: a policy that grants an owner power over an
editor's link, without a page that shows it, grants a power only reachable by someone who already
knows the identifier.

The names on it are decrypted in the browser, because the server can say a link exists and when it
expires but not what it points at. Where a name cannot be recovered the page distinguishes the two
reasons — a secret since deleted, and a vault the user has been removed from — rather than showing a
blank row.

---

## Phase 10 — Key lifecycle at scale

**Size: L.** Phase 5 built re-keying because revocation demanded it. This phase makes key
management a routine, testable operation rather than an emergency one.

### Tasks

1. **Voluntary vault key rotation** on demand, and optionally on a schedule, reusing phase 5's
   atomic re-key path.
2. **User identity key rotation**: a new X25519/Ed25519 pair. This is self-service — the user
   still holds their *old* private key, so their client can unwrap every Vault Key sealed to it
   and re-seal each one to the new public key in a single atomic submission. No vault owner needs
   to be involved and no Vault Key changes. Two things do need care: the new public key must be
   self-signed and republished, which invalidates every peer's pin and must trigger a re-verify
   prompt on their side rather than a silent accept; and rotation because a key was *compromised*
   should be accompanied by rotating the Vault Keys of every vault the user belongs to, which is a
   different and much more expensive operation. Offer both, and label them honestly.
3. **KDF parameter upgrades**, silent, on next login, per
   [03 § Parameter upgrades](03-cryptographic-design.md#parameter-upgrades).
4. **Envelope version migration**: introduce a `v2`/`alg=2` and lazily re-wrap on write, proving
   the algorithm agility designed in phase 1 actually works. Doing this once, deliberately, is
   worth more than the abstraction it validates.
5. A verification command reporting, per vault: epoch consistency, unreachable item keys,
   memberships stranded on an old epoch.
6. Health dashboard: vaults needing re-key, users on stale KDF params, items on old envelope
   versions.

### Exit criteria

Rotate a vault key, a user's identity keys and the KDF parameters — each without data loss and
each verifiable. Run a full v1 → v2 envelope migration on a seeded database. The verification
command reports clean, and reports correctly when a fault is injected.

---

## Phase 11 — Hardening & verification

**Size: L.** Phase 0 set the baseline. This phase attacks it.

### Tasks

1. CSP audit: confirm no `unsafe-inline`/`unsafe-eval` in `script-src` in production (SR10, as an
   automated header assertion). Add `require-trusted-types-for 'script'` and a Trusted Types
   policy; fix whatever it breaks.
2. **Subresource integrity** on built bundles, generated at build time and injected into the
   Blade shell.
3. Full header review: HSTS with preload, COOP/COEP/CORP, `Permissions-Policy` denying camera
   (except where phase 9 needs it), microphone, geolocation and USB.
4. Rate limiting review across every endpoint, not just auth. Per-account and per-IP.
5. **Timing analysis** on auth and KDF-params endpoints; confirm the decoy path does not diverge
   measurably.
6. Dependency review: pin, lock, audit, and re-read the `@noble` changelogs for anything that
   moved since phase 1.
7. `SECURITY.md` with a disclosure policy.
8. **A written self-directed penetration test**, worked through and documented: OWASP Top 10 and
   ASVS L2 against the running app. IDOR, mass assignment, SSRF via any URL field, XSS in every
   rendered field, CSRF, session fixation, open redirect, host-header injection.
9. ZAP baseline scan in CI.
10. **The honest disclosure page in the product itself** — not only in `docs/` — stating that a
    compromised server can serve malicious JavaScript, in plain language, where a user will see it
    (D10, A3). The threat model belongs in the UI, not just the repo.
11. Backup encryption and restore verification.

### Exit criteria

Every requirement SR1–SR10 in [02](02-threat-model.md#security-requirements) has a passing
automated test. The pen-test document is complete with findings and resolutions. ZAP baseline is
clean or every finding is triaged in writing.

---

## Phase 12 — Operations & release

**Size: M.**

### Tasks

1. Deployment: Laravel Cloud or a hardened VPS. TLS 1.3, automated certificates, Postgres with
   encryption at rest (belt and braces — the data is already ciphertext).
2. Backup and **restore rehearsal**. A backup you have not restored is a hypothesis. Restore into
   a scratch environment and unlock a real vault from it.
3. **Full client-side export** to an encrypted archive and to plaintext JSON with a deliberately
   heavy warning. Non-negotiable for a tool that can permanently lose your data — and it is what
   makes D3's "no recovery path" ethically defensible.
4. Monitoring: uptime, error tracking **with body scrubbing verified**, audit anomaly alerts
   (mass reads, repeated failed unlocks, recovery use).
5. Log hygiene: retention, no request bodies on secret endpoints, hashed IPs.
6. Operator runbook: onboarding a user, rotating a compromised key, restoring from backup,
   responding to a suspected server compromise.
7. `README.md` rewrite, and a walkthrough of the cryptographic design for a reader who is
   evaluating whether to trust it.
8. **A retrospective document**: what the zero-knowledge constraint actually cost, which decisions
   would change, and what surprised you. This is the deliverable that makes the project pay back
   as a learning exercise rather than just a working app.

### Exit criteria

Deployed, monitored, backed up, restore-tested, exportable, documented.

---

## Cross-cutting practices

Applied in every phase, not saved for phase 11:

- **Tests are written with the feature, not after it.** The leak canary and the AAD-binding tests
  in particular are regression nets for the entire project.
- **Every crypto change updates [03](03-cryptographic-design.md) first,** then the code.
- **Every rejected alternative gets written down** — in an ADR or in the rejected table in 03.
  Six months from now the reasoning is worth more than the decision.
- `record-rule` for anything a future session must not get wrong.
- **No `dd()`, no `dump()`, no `console.log` of anything downstream of a decrypt.** Add a lint
  rule; do not rely on discipline.
- Ask, at every phase: *what does the server learn that it did not learn before?* If the answer is
  anything, it goes in [02 § Accepted leakage](02-threat-model.md#accepted-leakage) or it gets
  designed out.
