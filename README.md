# Vault

A zero-knowledge, end-to-end encrypted secret manager. The server stores ciphertext and wrapped
keys, and holds no key capable of decrypting any of it.

This is a ground-up rebuild of a [2017 project of mine](https://github.com/theprivateer/vault-2017) that got the structure right and the
cryptography wrong: it encrypted secrets at rest with a single application-wide key, then decrypted
them on the server before rendering. Anyone with the database and the `.env` had everything. This
version moves the trust boundary into the browser.

**It is built to learn from, not to sell.** The interesting artefact is
[`docs/`](docs/) — the threat model, the cryptographic design, and the reasoning behind each
decision including the ones that were rejected.

## How it works, in one paragraph

Your password is stretched with Argon2id **in your browser** into two independent keys: a
key-encryption key that never leaves the device, and an auth key that is all the server ever sees
(and only ever as a slow hash). The KEK unwraps a random per-account **User Key**, which unwraps
your X25519 and Ed25519 private keys. Each vault has a random **Vault Key**, sealed individually to
each member's public key. Each item — vault, lockbox, secret — has its own **Item Key** wrapped by
the Vault Key, so rotating a vault costs a re-wrap of 32-byte blobs rather than re-encrypting
everything. Every ciphertext is bound by AEAD associated data to the exact record it belongs to, so
a malicious server cannot move one ciphertext into another record's place. Names, notes and types
all live inside the encrypted payload, so search happens in the browser.

## What that looks like in the database

A vault called "Production Infrastructure", holding a secret whose value is `hunter2-the-real-one`:

```
INSERT INTO vaults    VALUES(1,'01a0024a-2847-…',1,'AQHQ5WS1D1CVNg7geMG4AlHln6L4k5/Qxx9C5kZN60c9…
INSERT INTO lockboxes VALUES(1,'01a0024a-2850-…',1,'AQExfPmBs2PDMI23HwdKwnFY/yGoESzXb0BAPEk1nz9n…
INSERT INTO secrets   VALUES(1,'01a0024a-2851-…',1,'AQFPkKYiNf23AnhW8KKdDOQnSx7IIgHt0IoqKEhx9atj…
```

Those three rows are also all padded to bucket sizes before encryption, so their stored lengths
say which bucket rather than how long the password is.

Grepping the whole dump for any of that plaintext returns nothing. The only readable columns are
the identifier, the timestamps, the payload version and the key epoch — each one listed in
[`docs/04-data-model.md`](docs/04-data-model.md) with the reason it is not encrypted. A
[leak canary test](docs/06-testing-and-ci.md) asserts this on every commit, sweeping every table,
log file, cache entry and storage disk for a sentinel value.

## What it does not defend against

**A compromised server can serve you malicious JavaScript.** No amount of browser-delivered
cryptography fixes that, and any product claiming otherwise is not being straight with you. It is
written down as adversary A3 in the [threat model](docs/02-threat-model.md), it is stated in the
application's own interface, and it is the main argument for self-hosting this rather than trusting
someone else's deployment.

Other honest limitations:

- **"Read-only" is a server-side rule, not a cryptographic one.** Every member of a vault holds the
  Vault Key, so a viewer who wants a copy of a secret can take one. Roles stop people *changing*
  things.
- **Lose your password and your recovery kit and the data is gone.** There is no reset, because the
  server cannot re-wrap a key it cannot unwrap. This is the cost of the design, not an oversight.
- **The sharing graph is visible.** Who shares what with whom, and when. Hiding it needs private
  information retrieval, which is out of scope.

## Documentation

Read in this order:

| Doc | What it covers |
| --- | --- |
| [01 — Brief & Decisions](docs/01-brief-and-decisions.md) | Goals, scope, the twelve settled decisions and their rationale |
| [02 — Threat Model](docs/02-threat-model.md) | Assets, adversaries, what is and is not protected, accepted leakage |
| [03 — Cryptographic Design](docs/03-cryptographic-design.md) | Key hierarchy, primitives, envelope format, every protocol flow |
| [04 — Data Model](docs/04-data-model.md) | Schema, and what each unencrypted column leaks |
| [05 — Implementation Plan](docs/05-implementation-plan.md) | Thirteen phases, each with deliverables and exit criteria |
| [06 — Testing & CI](docs/06-testing-and-ci.md) | The four tests that matter most, and the CI gates |
| [adr/](docs/adr/) | Decision records — what was chosen, and what was rejected |

## Status

Phases 0–10 of [thirteen](docs/05-implementation-plan.md) are complete: a working zero-knowledge
vault that can be shared with other people and taken back, holds encrypted attachments, keeps a
tamper-evident log of what happened in it, remembers what its secrets used to say, can hand a single
credential to somebody who has no account at all, and treats key rotation as a routine operation
rather than an emergency one.

- **Phase 0** — Inertia + Vue + TypeScript strict, a nonce-based CSP enforced from the first
  render, static analysis at maximum, CI gating every check.
- **Phase 1** — the crypto core: envelope format with mandatory AAD binding, the key hierarchy,
  sealed boxes, identities, and the crypto Worker. Verified against RFC vectors and cross-checked
  byte-for-byte against PHP's `ext-sodium`.
- **Phase 2** — invite-only registration, split-key login, the recovery kit, password change, TOTP,
  and the unlock state machine.
- **Phase 3** — vaults, lockboxes and secrets, end to end, plus the leak canary and the IDOR suite.
- **Phase 4** — the decrypted-item store and its synchronous wipe on lock, bulk decryption in the
  Worker, client-side search, payload padding, optimistic writes with concurrent-edit detection,
  and the scale ceiling measured rather than guessed at.

- **Phase 5** — sharing by signed grant, trust-on-first-use fingerprint pinning with a hard stop
  when a key changes, and revocation that triggers an atomic re-key. The phase where the
  asymmetric layer earns its place. Ownership transfer closes it out, and is the one write here
  that carries no key material at all: the recipient already holds the Vault Key, so handing a
  vault over moves who may administer it and re-encrypts nothing. A vault with other members
  refuses to be deleted, since their access *is* a sealed copy of that key.
- **Phase 6** — encrypted file attachments: chunked AES-256-GCM through WebCrypto, with each
  chunk's index and its file's chunk count bound into the associated data, so truncation and
  reordering fail the tag rather than an application check. Resumable uploads, per-vault quotas, and
  filenames that exist only inside the encrypted manifest.
- **Phase 7** — a tamper-evident audit log: a BLAKE2b chain over every action, append-only, with the
  chain head mailed to the operator daily. The two events the server cannot witness — a vault
  unlocked, a secret revealed — are reported by the browser and signed, so the one thing a
  compromised server could invent is the one thing it cannot.
- **Phase 8** — version history: an edit appends rather than overwrites, and the archived payload is
  a fresh encryption bound to its own identity rather than a copy of the column it replaced — which
  is what stops a server writing an old password back over the current one. Diffing is client-side,
  restoring is an ordinary edit and therefore never destructive, and retention plus an outright
  purge bound how long a rotated credential stays recoverable.

- **Phase 9** — TOTP codes generated in the browser from a seed stored like any other field, password
  and passphrase generators whose entropy is arithmetic rather than an estimate, and one-time share
  links. A link carries its own key in the URL fragment, so the server holds a payload it cannot read
  and a hash it cannot reverse; putting the bearer token there too keeps it out of every access log
  and means a chat client's link preview cannot spend the single view.

- **Phase 10** — key lifecycle: vault keys rotated on demand rather than only after a revocation,
  identity keys replaced **without anybody else acting** — you still hold the old private key, so
  your own browser re-seals every vault key to the new pair — and Argon2id parameters re-run silently
  on the next login, which is the only moment a browser holds the password. A rotation is announced
  by a notice signed with the key being retired, so a peer can tell "they rotated" from "the server
  substituted a key"; it changes what the warning says and never whether it appears, because a stolen
  key signs an equally valid notice. Moving old ciphertext onto a new envelope format is an operation
  rather than a migration — the server cannot re-seal what it cannot read — so a vault owner runs it
  from the browser, and it carries a compare-and-swap so a stale tab cannot write old plaintext back
  under a new wrapper.

Next is [Phase 11](docs/05-implementation-plan.md#phase-11--hardening--verification): hardening and
verification.

## Stack

- **Backend** — Laravel 13, PHP 8.4 with `ext-sodium`, Pest 5, Larastan at max level
- **Frontend** — Inertia 3 + Vue 3 + TypeScript (strict), Tailwind 4, Vite 8
- **Crypto** — `@noble/ciphers`, `@noble/curves`, `@noble/hashes` in the browser. Audited, pure
  TypeScript, no WASM — which is what lets the CSP stay free of `wasm-unsafe-eval`. **Nothing on
  the server.**

XChaCha20-Poly1305 for encryption, Argon2id for password stretching, HKDF-SHA256 for key
derivation, X25519 for sealed boxes, Ed25519 for signatures, BLAKE2b for fingerprints.

## Running it locally

```bash
composer setup      # install, key:generate, migrate, build assets
php artisan dev     # serve, queue, logs and Vite together
```

Registration is invite-only, so the first account needs an invitation from the command line:

```bash
php artisan vault:invite you@example.com
```

That prints a single-use link. Open it, choose a master password, and **write down the recovery kit
it gives you** — it is shown once, and nothing can reissue it if you lose the password too.

### One thing to remember

The crypto Worker is built to a fixed path rather than served through Vite, because a Worker must
be same-origin with the page and the dev server is not. So it is **not hot-reloaded**:

```bash
npm run build:worker    # after changing anything in resources/js/crypto
```

That is a deliberate trade. The one part of this codebase that should never be swapped out
invisibly is the part holding the keys.

## Development

```bash
php artisan test              # Pest
npm run test                  # Vitest
npm run test:coverage         # enforces 100% coverage of resources/js/crypto
npm run types                 # tsc --noEmit
npm run lint                  # ESLint
vendor/bin/pint               # formatting
vendor/bin/phpstan analyse    # static analysis at max level
npm run bench:vault           # the scale ceiling, at 100 / 1,000 / 10,000 secrets
npm run bench:argon2          # password stretching cost
```

CI runs all of the above on every push, apart from the two benchmarks, which are run by hand when
a number needs revisiting. Several of the tests are load-bearing security controls
rather than regression checks — the leak canary, the AAD-binding suite, the bit-flip integrity
tests and the IDOR suite. [`docs/06`](docs/06-testing-and-ci.md) explains why each one exists.

Settled decisions and non-obvious traps live in [`.ai/rules`](.ai/rules/), indexed by the paths they
apply to, so they survive into future sessions instead of being rediscovered.

## Contributing

This is a personal learning project rather than something seeking contributors, but if you spot a
flaw in the cryptographic design or the threat model I would genuinely like to know — that is the
most useful thing anyone could offer it. Open an issue.

## Licence

[MIT](LICENSE). Do what you like with it.

**A caveat that matters more than the licence.** This has not been independently audited, and it is
a project I built to learn how these systems are put together. Read the threat model before you
trust it with anything you would mind losing.
