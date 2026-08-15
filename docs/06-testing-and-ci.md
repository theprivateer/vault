# 06 — Testing & CI

In a system where a bug means silent plaintext disclosure, tests are the security control. This
document names the tests that carry the most weight, so they are built deliberately rather than
accumulated.

## The four tests that matter most

If everything else were deleted, these four would still catch the failures that actually
matter in this design.

### 1. The leak canary (SR1) — Phase 3

```
create a secret whose value is a unique random sentinel
  → grep every database table
  → grep storage/logs/*
  → grep the cache and queue tables
  → grep every configured filesystem disk
  → fail if the sentinel appears anywhere
```

Highest value test in the project. It catches the failure mode that code review does not: a
well-meaning future change — an eager-loaded relation serialised into a log line, a debug helper,
an exception report body, a queued job payload — that quietly reintroduces server-side plaintext.
Runs on every commit.

**As built** (`tests/Feature/Vault/LeakCanaryTest.php`), with three refinements that came out of
writing it:

- **Two sentinels, for two different mistakes.** One is sealed inside a real
  XChaCha20-Poly1305 envelope built with `ext-sodium` — if it ever appears in the clear, something
  decrypted it. The other is posted in plaintext in fields the API does not use, as a buggy client
  would send them — if *that* appears, some path is persisting or logging raw request input.
- **A guard against a vacuous pass.** The test asserts the row was actually written and that its
  ciphertext *is* in the haystack. A canary that passes because nothing was stored is worse than
  no canary, because it reads as evidence.
- **A self-test.** A third case plants a marker in a table, a log file and the cache, then asserts
  the sweep finds all three. Otherwise a sweep that silently stopped covering something would
  leave two green tests guarding nothing.

The rejected-request case matters as much as the accepted one: a handler that logged request
bodies would leak on exactly the path nobody exercises.

#### Verified by hand, once

The exit criterion for Phase 3 was to look at the database directly. Every row for a vault named
"Production Infrastructure", holding a secret whose value was `hunter2-the-real-one`:

```
INSERT INTO vaults VALUES(1,'01a0024a-2847-…',1,'AQHQ5WS1D1CVNg7geMG4AlHln6L4k5/Qxx9C5kZN60c9…
INSERT INTO lockboxes VALUES(1,'01a0024a-2850-…',1,'AQExfPmBs2PDMI23HwdKwnFY/yGoESzXb0BAPEk1…
INSERT INTO secrets VALUES(1,'01a0024a-2851-…',1,'AQFPkKYiNf23AnhW8KKdDOQnSx7IIgHt0IoqKEhx9a…
```

Grepping the whole dump for `Production Infrastructure`, `AWS Root Account`, `root password` and
`hunter2-the-real-one` returns zero occurrences of each. The only plaintext on those rows is the
identifier, the timestamps, the payload version and the key epoch — all of it named in
[04](04-data-model.md) with its reason. In 2017 the same query would have returned the vault's
name in the clear and a value one application key away from it.

#### Padding, verified the same way

The exit criterion for the Phase 4 padding work was to see the effect on stored sizes rather than
trust the unit tests. Eight real secrets, sealed through the actual stack, measured in bytes:

| secret | JSON | stored, unpadded | stored, padded |
| --- | ---: | ---: | ---: |
| a 4-digit PIN | 64 | 106 | **170** |
| `hunter2` | 67 | 109 | **170** |
| a 13-character password | 73 | 115 | **170** |
| a 15-character password | 75 | 117 | **170** |
| a 41-character API token | 101 | 143 | **170** |
| a 46-character passphrase | 106 | 148 | **170** |
| an SSH private key | 972 | 1,014 | 1,066 |
| a 3,000-character note | 3,060 | 3,102 | 4,138 |

The first six rows are the point. Unpadded, the stored length is the length of the secret plus a
constant — a server reading its own database learns that one credential is a PIN and another is a
41-character token without decrypting anything. Padded, all six are byte-identical at 170, and
what remains visible is only that the last two are *bigger*, which is the accepted leakage written
down in [02 § Accepted leakage](02-threat-model.md#accepted-leakage).

### 2. AAD binding (SR4) — Phase 1

Seal a payload under record A's associated data; attempt to open it as record B; assert
`IntegrityError`. One test per AAD context, plus one that swaps a `viewer`'s wrapped vault key for
an `owner`'s. Without these, the whole ciphertext-relocation attack class is untested.

### 3. Bit-flip integrity (SR3) — Phase 1

For a short envelope, flip **every bit position** in turn and assert every one throws. Directly
codifies the inverse of the 2017 bug, where `DecryptException` was caught and `null` returned.
Extend with truncation, extension and nonce-swap cases.

### 4. Key material storage (SR7) — Phase 2

After unlock, assert `localStorage`, `sessionStorage`, IndexedDB and all cookies are free of key
material. Written in Phase 2 and guarding every phase after it, because this is a property that
degrades by accident — someone adds "remember this vault" and stores the wrong thing.

## Backend — Pest 5

- **Feature tests per endpoint.** Every route gets the happy path, the unauthenticated case, the
  unauthorised case and the malformed-input case.
- **Policy tests, table-driven.** A row per (role × action × resource). Exhaustive, boring,
  exactly the kind of thing that is skipped and then regretted.
- **IDOR suite.** For every resource, user B gets **404** on user A's records. 404 rather than
  403 — a 403 confirms the resource exists.
- **Validation tests** proving the server accepts only blob shape and size, and that no code path
  parses a payload.
- **Chain verification** (Phase 7) with deliberate corruption: modify a row, delete a row, reorder
  two rows; each must be detected and the first divergent `seq` reported.
- **Enumeration tests** on `/auth/kdf-params` and login: unknown, known and malformed emails all
  return the same shape.
- **Throttle tests** for per-IP and per-account limits.
- Factories that produce **realistic ciphertext** — generated by the real crypto module through a
  Node bridge, not random bytes. Random-byte fixtures let AAD bugs pass.

## Frontend — Vitest

- 100% branch coverage on `resources/js/crypto/**`, gated in CI. Coverage elsewhere is
  informational.
- Known-answer tests from RFC 8439, 7748, 8032, 9106 and 5869, with vectors committed as fixtures.
- Property-based round-trip tests across sizes including 0 and 1 byte.
- Worker protocol tests, including that key material never appears in a message *out* of the
  Worker.
- Store tests: lock wipes state synchronously, **and a decrypt already in flight when the lock
  happens discards its results rather than refilling the store it just emptied**.
- Padding tests: two secrets of different length are stored at the same size, and an unpadded
  version 1 payload still opens.
- **Search is offline, asserted rather than described:** `fetch`, `XMLHttpRequest`, `WebSocket`,
  `EventSource` and `sendBeacon` are replaced with functions that throw, and a query still
  returns. The manual version is to switch the network off in DevTools and keep typing.
- **A cross-implementation test** comparing a sample of outputs against PHP's `ext-sodium`, to
  catch an encoding or endianness error that JS would otherwise agree with itself about.

## The scale ceiling, measured

D5 puts every name and note inside the ciphertext, so the server cannot search and the browser has
to hold the whole vault. That is only a defensible trade if somebody has measured what it costs.
`npm run bench:vault` does, at three orders of magnitude.

Apple M1, Node v22.23.2, payloads the shape of real credentials (name, value, notes, URL — around
190 bytes of JSON, padded to the 256-byte bucket):

| secrets | decrypt, batched | decrypt, one at a time | worker messages, batched → serial | build index | per query | ciphertext | heap held |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 100 | 6 ms | 7 ms | 2 → 100 | 1 ms | 0.06 ms | 0.03 MiB | ~0 MiB |
| 1,000 | 24 ms | 35 ms | 16 → 1,000 | 5 ms | 0.06 ms | 0.3 MiB | ~1 MiB |
| 10,000 | 184 ms | 320 ms | 157 → 10,000 | 43 ms | 0.51 ms | 2.8 MiB | ~16 MiB |

**Against the exit criterion.** A 1,000-secret vault opens in 24 ms of decryption and 5 ms of
indexing, against a budget of two seconds. There is no meaningful pressure here at all.

**The honest reading of the "one at a time" column.** The benchmark runs the handler in-process,
so it charges a `structuredClone` per message but not the thread hop a real Worker pays. The
timings therefore understate the batching win, possibly by a lot. The message counts beside them
do not depend on that model, and they are the real argument: opening a thousand secrets went from
a thousand round trips to sixteen.

**Where the ceiling actually is, and it is not the cryptography.** At 10,000 secrets the decrypt
costs 184 ms — while unlocking the vault at all costs ~731 ms of Argon2id (ADR-0003). Opening a
vault four times the size of anyone's would still be cheaper than the password stretch that
precedes it. The binding constraints, in order:

1. **Transfer.** 2.8 MiB of ciphertext is ~3.8 MiB base64 on the wire, sent on every visit to a
   vault page. This is the first thing that will hurt, and the fix when it does is an Inertia
   partial reload rather than a change to the cryptography.
2. **Heap.** ~16 MiB of decrypted plaintext and index at 10,000 items. Fine in a tab; worth
   remembering that all of it is secrets, which is why the store is wiped synchronously on lock.
3. **Search.** 0.51 ms per query at 10,000 — still imperceptible, and it is the linear prefix scan
   in `lib/search.ts` that grows here. A trie is the answer if it ever stops being imperceptible.

**Which is the answer to "why not blind indexes".** A server-side searchable encryption scheme
would buy a decrypt cost that is already 184 ms at a vault size nobody has, and would sell a
per-keyword equality oracle to the server in exchange. The measurement is what says we do not need
to make that trade — not a preference.

Caveat, the same one as ADR-0003: Node and a desktop browser are both V8, so this stands in for a
laptop and not for a phone. Phone numbers need a real device.

## End-to-end — Playwright

- Register → recovery kit → logout → login → unlock → create → read → lock.
- Two-user sharing with fingerprint verification.
- **Malicious-server simulation:** intercept responses and corrupt a ciphertext, swap a public
  key, forge a membership row without a valid signature. Each must produce a visible, specific
  error — never silent corruption and never a quiet accept. This is the closest thing to testing
  the threat model directly.
- Revoke → re-key → confirm the old epoch is gone.
- Storage assertions (test 4 above) at every step of the flow.
- CSP violation listener that fails the test on any violation.

## CI gates

Every gate blocks merge.

| Gate | Tool |
| --- | --- |
| PHP style | `vendor/bin/pint --test` |
| PHP static analysis | Larastan, max level |
| PHP tests + coverage | `php artisan test --coverage` |
| **Leak canary** | Pest, its own job so a failure is unmissable |
| **No decrypt in `app/`** | grep gate for `decrypt`, `Crypt::`, `openssl_`, `sodium_crypto_*_open` (SR2) |
| TS types | `tsc --noEmit` |
| JS lint | ESLint, including `no-restricted-imports` keeping the crypto module app-free |
| JS tests | Vitest, 100% on `crypto/**` |
| E2E | Playwright |
| Dependencies | `composer audit`, `npm audit`, Dependabot |
| Headers | assertion test for the production CSP (SR10) |
| DAST | ZAP baseline |

## Deliberately not tested

Named so they are choices, not gaps:

- **Cryptographic primitives themselves.** We test that we *use* them correctly. Verifying
  ChaCha20 is `@noble`'s job and its auditors'.
- **Constant-time behaviour of the JS implementations.** Not meaningfully testable in a JIT
  runtime. Trusted from `@noble`'s design and documentation.
- **Argon2id resistance.** Parameters are chosen from OWASP guidance and benchmarked, not tested.
- **The A3 threat** (malicious served JavaScript). Untestable from inside the system, by
  definition. This is the one to keep saying out loud.
