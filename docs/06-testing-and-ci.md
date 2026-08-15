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

### 1b. Sharing, and what each half can prove — Phase 5

Sharing is the one feature whose tests have to be split across two suites, because the two halves
defend against different things and neither can stand in for the other.

**In Pest** (`tests/Feature/Vault/SharingTest.php`, `RekeyTest.php`, `RoleMatrixTest.php`) —
everything the server is actually responsible for. That it stores exactly the bytes it was given;
that revocation cuts access on the *next request*, before any re-key; that a re-key is refused
unless the set is complete and the epoch is exactly current + 1; and a table with a row per
(role × action) because role checks are the one part of this system with no cryptographic
backstop.

**In Vitest** (`resources/js/lib/sharing.test.ts`) — the two exit criteria no server is involved
in, against real generated keys:

- a grant whose signature was tampered with is rejected by the recipient, and
- a **substituted public key produces a hard stop**: a bundle that is internally perfect — valid
  self-signature, matching fingerprint — is caught only by not matching what was pinned.

The second is the interesting one, and its sibling cases are what give it teeth. A genuine grant
stapled to a row claiming `owner`; a genuine grant replayed against a different vault; a genuine
grant replayed against a recipient whose keys were swapped after it was issued; a bundle pairing
one identity's signing key with another's encryption key. All verify as *signatures*. All are
refused, and each for a different reason.

**What is deliberately not asserted server-side:** that a signature is valid. The server serves
the public key too, so checking a signature against it would be checking its own work. It compares
the signed grant with the row for the same reason a compiler warns about unused variables — to
catch mistakes, not attackers — and that distinction is written into the controller so nobody
later mistakes it for a security control.

### 2. AAD binding (SR4) — Phase 1

Seal a payload under record A's associated data; attempt to open it as record B; assert
`IntegrityError`. One test per AAD context, plus one that swaps a `viewer`'s wrapped vault key for
an `owner`'s. Without these, the whole ciphertext-relocation attack class is untested.

### 3. Bit-flip integrity (SR3) — Phase 1

For a short envelope, flip **every bit position** in turn and assert every one throws. Directly
codifies the inverse of the 2017 bug, where `DecryptException` was caught and `null` returned.
Extend with truncation, extension and nonce-swap cases.

### 3b. Chunk binding, and a dishonest server — Phase 6

A file is the one thing here made of many ciphertexts that have to arrive in a particular order, so
it has an attack surface the single-payload items do not: drop the last chunk, swap two, replay one
from another file. All three are stopped by the same mechanism — the chunk's index and its file's
chunk count are inside the AAD — and none of them is stopped by application code, which is the
point. **No length comparison anywhere detects a truncated file; the tag does.**

Tested in two places, deliberately, because they prove different things:

- `resources/js/crypto/chunks.test.ts` proves the cipher's own guarantee, one operation at a time.
- `resources/js/lib/files.test.ts` mounts the same attacks across a whole round trip, with the real
  Worker in-process and a fake server that stores what it is given and hands back **whatever it is
  told to**. That server is as dishonest as a compromised one: it swaps chunks, drops the last, and
  shortens the chunk count it reports on the row. The last of those is the interesting case — it
  fails to do anything, because the count the client loops on came out of the encrypted manifest,
  and that is a property of where a number is read from rather than of any check.

### 3c. The audit chain, and what it cannot prove — Phase 7

Four kinds of tampering, each caught by a different property, each with its own deliberate-corruption
test in `tests/Feature/Vault/AuditChainTest.php`:

| Tampering | What catches it |
| --- | --- |
| A field changed | the row's stored hash no longer equals the hash of its own contents |
| A row deleted | `seq` jumps — which is why it is gapless rather than merely increasing |
| Two rows reordered | the chain of `prev_hash` values, since nothing is missing and no count changed |
| Rows removed from the end | **nothing in the chain.** What remains is a valid shorter chain |

That last row is the interesting one, and it is why the table has a stored head and why the head is
mailed out daily. The corruption tests write with the raw query builder rather than through the
model, on purpose: `AuditEvent` refuses to be updated or deleted, and a test that only exercised
that guard would prove something about application code rather than about the chain.

**What none of it proves** is that the log was not written wholesale by a server that also holds
every input to the hash. Only the signatures speak to that, so `AuditSignatureTest.php` includes the
case the signing design exists for: an entry fabricated after the fact with every subsequent hash
recomputed, so the chain verifies perfectly and only the signature gives it away.

The metadata linter lives here too, in two forms — a structural assertion that every declared key is
an allow-listed shape, and a canary that posts a sentinel through the real endpoints in every field
a careless client might use and asserts it reaches no audit row.

### 3d. The version that could pass for the present — Phase 8

Version history creates one attack that nothing before it could: an archived payload written back
over the live row, silently restoring a credential that was rotated *because it leaked*. It works
if and only if the two ciphertexts share a binding, which is exactly what a server-side copy of
`secrets.payload_ct` would produce.

So the archive is a separate encryption under `secret.version.payload` at the version row's own
UUID, and `resources/js/lib/history.test.ts` runs the substitution in both directions — an archive
offered as the live payload, and an archive offered under a different version's identity — and
expects a tag failure each time. Neither is caught by a check anybody wrote; both are caught by the
AEAD, which is the same shape of answer as the chunk-count binding above.

The server-side half is in `tests/Feature/Vault/HistoryTest.php`, and the case worth naming is the
one that asserts a *losing* concurrent edit leaves no archive behind. Without the archive inside the
transaction that guards the update, the loser's browser would have contributed a version to a
history whose corresponding edit never happened — a history that is honest about edits that
succeeded is most of what makes it worth reading.

### 4. Key material storage (SR7) — outstanding, Phase 11

After unlock, assert `localStorage`, `sessionStorage`, IndexedDB and all cookies are free of key
material. This is a property that degrades by accident — someone adds "remember this vault" and
stores the wrong thing — which is exactly why it wants a test rather than a convention.

**It does not have one yet, and saying otherwise would be the wrong kind of comfort.** What holds
today is stronger than a convention and weaker than a test: no code in `resources/js` calls any of
those storage APIs at all, so there is nothing to leak through. But "nobody has written the call
yet" is a fact about the present, and the failure this test exists to catch is a future commit. It
needs the browser context that the Phase 11 E2E suite brings, and it is the first thing that suite
should assert.

## Backend — Pest 5

- **Feature tests per endpoint.** Every route gets the happy path, the unauthenticated case, the
  unauthorised case and the malformed-input case.
- **Policy tests, table-driven.** A row per (role × action × resource). Exhaustive, boring,
  exactly the kind of thing that is skipped and then regretted. One trap found while writing it:
  the actions are not independent when they share a fixture, because `delete vault` succeeds and
  soft-deletes it, after which every later action answers 404 — which reads exactly like a
  permission failure and hid most of the row. Each action gets its own fixture.
- **IDOR suite.** For every resource, user B gets **404** on user A's records. 404 rather than
  403 — a 403 confirms the resource exists.
- **Validation tests** proving the server accepts only blob shape and size, and that no code path
  parses a payload.
- **Chain verification** with deliberate corruption: modify a row, delete a row, reorder two rows;
  each must be detected and the first divergent `seq` reported. Plus the two the exit criteria did
  not ask for — truncation from the end and a rewritten head — because neither is caught by the
  chain itself ([3c above](#3c-the-audit-chain-and-what-it-cannot-prove--phase-7)).
- **File tests** covering the parts of an attachment the server is responsible for: chunk
  idempotency, the quota counted in stored bytes rather than declared ones, refusal of an
  out-of-range index or an unrecognised algorithm byte, and the sweep that removes abandoned
  uploads and purged files. Plus one that reads the fake disk back and asserts every path is a
  random UUID with no extension — the direct answer to 2017, where a directory listing was a table
  of contents.
- **Enumeration tests** on `/auth/kdf-params` and login: unknown, known and malformed emails all
  return the same shape.
- **Throttle tests** for per-IP and per-account limits.
- Factories that produce **correctly shaped envelopes** (`database/factories/EnvelopeFixtures.php`)
  — a real version and algorithm byte, a real nonce length, random noise for the body.

  The original plan here was to generate genuine ciphertext through a Node bridge, on the grounds
  that random-byte fixtures let AAD bugs pass. That was the wrong instinct, and writing it made the
  reason clear: **nothing on the server can decrypt an envelope**, so a fixture that could be
  decrypted would exercise a path the application does not have. AAD binding is proved in the
  crypto suite against real keys, where it can actually fail. What the server-side fixtures have to
  get right is the header, because that is all the server ever looks at — and if they got it wrong,
  factories and request validation would quietly drift apart.

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
- File tests that run a real upload and download against a fake server
  ([3b above](#3b-chunk-binding-and-a-dishonest-server--phase-6)), including a resume that refuses
  when the source has changed — because resuming re-encrypts a chunk at a nonce it has already
  used, and doing that with different bytes is nonce reuse under GCM.

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

## End-to-end — Playwright (Phase 11, not yet built)

Everything in this section is planned rather than running. It is listed here because several
requirements in [02](02-threat-model.md#security-requirements) have nowhere else to be verified —
SR7 in particular — and a plan that names them is what stops them being quietly dropped.

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

Every gate listed as running blocks merge, across three jobs in `.github/workflows/ci.yml`.

| Gate | Tool | Status |
| --- | --- | --- |
| PHP style | `vendor/bin/pint --test` | running |
| PHP static analysis | Larastan, max level | running |
| PHP tests + coverage | `php artisan test --coverage` | running |
| **Leak canary** | Pest — currently inside the backend job rather than its own | running |
| **No decrypt in `app/`** | `NoServerDecryptionTest` (SR2), run again as its own job | running, in the security job |
| Headers | `SecurityHeadersTest`, asserted against real Vite output (SR10) | running, inside the PHP suite |
| TS types | `vue-tsc --noEmit` | running |
| JS lint | ESLint, including `no-restricted-imports` keeping the crypto module app-free | running |
| JS format | `prettier --check` | running |
| JS tests | Vitest, 100% on `crypto/**` | running |
| Dependencies | `composer audit`, `npm audit --audit-level=moderate` | running |
| Dependabot | — | not configured |
| E2E | Playwright | Phase 11 |
| DAST | ZAP baseline | Phase 11 |

The leak canary was specified as its own job "so a failure is unmissable". It runs inside the
backend suite instead, which is a real if minor loss — a red backend job does not say *which*
guarantee broke. Worth splitting out when the CI file is next touched.

**The SR2 gate used to be a `grep` and it was broken.** It matched the *word* `decrypt`, which
meant `Ciphertext`'s docblock — the one that says it deliberately has no `decrypt()` method —
tripped the gate that docblock exists to explain, along with five other comments describing the
rule. A shell grep cannot tell a call from a prose sentence about calls. The security job now runs
`NoServerDecryptionTest` instead, which tokenises the PHP and strips comments before matching, and
which also asserts that its own patterns would still fire if a real call were added. It runs twice
on purpose: once inside the backend suite, and once as a named job so a failure of the single most
important rule here is a red check with the rule's name on it.

## Deliberately not tested

Named so they are choices, not gaps:

- **Cryptographic primitives themselves.** We test that we *use* them correctly. Verifying
  ChaCha20 is `@noble`'s job and its auditors'.
- **Constant-time behaviour of the JS implementations.** Not meaningfully testable in a JIT
  runtime. Trusted from `@noble`'s design and documentation.
- **Argon2id resistance.** Parameters are chosen from OWASP guidance and benchmarked, not tested.
- **The A3 threat** (malicious served JavaScript). Untestable from inside the system, by
  definition. This is the one to keep saying out loud.
