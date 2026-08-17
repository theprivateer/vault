# 08 — Retrospective

What the zero-knowledge constraint actually cost, what it did not, what surprised me, and what I
would do differently. Written at the end of Phase 12, before the thing has been deployed — which
is the right time for the first two sections and the wrong time for a verdict, so there is no
verdict here.

This is the document the [plan](05-implementation-plan.md) calls the deliverable that makes the
project pay back as a learning exercise rather than just a working application. It is written for
me in a year, and for anyone deciding whether to build one of these.

---

## What the constraint cost

Everything here follows from D1: the server must never hold a key that opens anything. Each item
below is a place where that turned into work, or into a worse experience, or into something that
simply cannot exist.

**The server cannot search, so the browser holds the whole vault.** D5 puts every name and note
inside the ciphertext, so a paginated list would either mean the server can read them or mean the
results are wrong. The browser downloads a vault and decrypts all of it. That is only defensible
if somebody measured it, so [06 § The scale ceiling](06-testing-and-ci.md#the-scale-ceiling-measured)
does: 10,000 secrets decrypt in 184 ms and occupy 2.8 MiB of ciphertext, against 731 ms of Argon2id
just to unlock. The binding constraint turned out to be *transfer*, not cryptography — and the
measurement is also what makes rejecting searchable encryption a decision rather than a preference,
because it says plainly that we would be buying a per-keyword equality oracle to fix a cost nobody
is paying.

**There is no password reset, so there had to be a way out.** D3 means the operator genuinely
cannot help you. That forced the recovery kit in Phase 2, and — much later than it should have —
the export in Phase 12. The export is not a feature. It is the thing that makes "your data is
permanently gone" an honest sentence rather than a hostage note: an application that will destroy
your data rather than hand it to the wrong person, and gives you no way to hold it yourself, has
not made a security decision, it has made you dependent on it. That reasoning arrived thirteen
phases late.

**Anything that needs a key is an operation, not a migration.** The server cannot re-encrypt what
it cannot read, so:

- a vault re-key needs a member's browser, which means it can never be scheduled, only reminded
  about;
- moving payloads onto envelope v2 is a page somebody clicks, not a migration — and the phrase
  "rows re-wrap lazily on write" turned out to mean "never, for exactly the data that matters
  most", which is why `/vaults/{id}/reseal` exists;
- archived versions can never move off envelope v1, because an archive that could be rewritten is
  a rollback channel for a credential that was rotated *because* it leaked;
- there is no import at all (D12), and the absence is partly this.

**Roles are not cryptographic, and the UI has to say so.** Every member of a vault holds the Vault
Key. "Viewer" stops somebody *changing* things; it cannot stop them taking a copy of what they can
already read. Any product that implies otherwise is describing a server-side rule as if it were a
mathematical one.

**The audit log cannot witness the two events that matter most.** A vault being unlocked and a
secret being revealed both happen entirely in the browser. So those two are reported by the client
and signed with the user's Ed25519 key — the one class of entry a compromised server cannot invent.
The cost is that the Worker becomes a signing oracle, which is why `AUDIT_ACTIONS` is a closed set:
it is the complete list of things injected script could make somebody's key say.

**Every ciphertext has to be bound to its record, by the client.** SR4. `seal()` takes associated
data as a required positional parameter with no default, so forgetting it is a type error rather
than a silent hole. The cost is that every call site has to know which record it is writing and at
what version — the AAD subject for a membership key is the *membership* UUID and not the vault's,
and getting that wrong would let a server move one member's sealed key onto another's row.

**Files needed their own everything.** Chunked AES-256-GCM through WebCrypto is the one place the
primitive changes, because a 100 MiB upload is the only place where hardware acceleration is the
difference between a progress bar and a hung tab. That brought a counted nonce (GCM's 96-bit nonce
cannot be generated randomly at scale), a manifest that lives inside the payload so the chunk count
in the AAD cannot come from the server, and a 100 MiB ceiling that exists only because reassembly
happens in a tab.

**Sharing needed the entire asymmetric layer, and a deliberately worse experience.** Signed grants,
fingerprint pinning, trust on first use — and a changed pin is a hard stop with no one-click
override, because a server substituting a key would substitute the fingerprint beside it. Even the
rotation certificate, which proves the old key introduced the new one, only changes the *wording*
of the warning and never the verdict: whoever stole the old key signs an equally valid notice.

**Two people editing one secret cannot be merged.** The two versions are ciphertext under different
item keys. The only options are refuse or silently lose one, so it refuses.

**Support is impossible by construction.** Nobody can look at a row and tell you what is wrong with
it. Every diagnostic in this application had to be built out of things the server can see —
structure, counts, versions, hashes — which is why `vault:health`, `vault:verify-keys` and
`vault:verify-backup` all exist and all end by saying what they did *not* check.

---

## What it did not cost

Worth stating, because the list above is long and one-sided.

**Performance was never the problem.** The fear going in was that pure-JS Argon2id would miss the
budget and force `hash-wasm`, and with it `'wasm-unsafe-eval'` in the CSP — a slower unlock traded
against a looser policy. It measured 731 ms on an M1 ([ADR-0003](adr/0003-argon2id-implementation.md)),
the question closed, and the CSP kept its strictness. A 1,000-secret vault opens in 24 ms of
decryption. At no point in thirteen phases did the cryptography become the slow part of anything.

**The dependency surface stayed genuinely small.** Three `@noble` packages, pinned exactly, audited,
pure TypeScript, no post-install scripts, no transitive dependencies. That was paid for twice — TOTP
is thirty lines of specified arithmetic instead of a package, and `zxcvbn-ts` was declined in favour
of a weaker in-house estimator that says on screen that it is weaker.

**A stolen database really is worthless.** This is the part that works. The leak canary sweeps every
table, every log file, the cache store and the storage disk for a sentinel on every commit, and
returns nothing. The 2017 version's entire failure mode is closed.

---

## What surprised me

### None of the real bugs were in the cryptography

Not one. The crypto core has 100% branch coverage, known-answer tests against five RFCs, bit-flip
tests over every position in a short envelope, and a byte-for-byte cross-check against PHP's
`ext-sodium`. It has never been the source of a defect.

Everything expensive happened in the ten metres around it:

| What broke | Category |
| --- | --- |
| Two endpoints served the encrypted file store outside the authorisation model ([F4](07-penetration-test.md)) | A framework default nobody chose |
| `Host:` was attacker-controlled input to URL generation ([F7](07-penetration-test.md)) | A framework default nobody chose |
| A `dontFlash` list drifted for eleven phases and wrote wrapped Item Keys into the session ([F11](07-penetration-test.md)) | A list that stopped matching the schema |
| Login answered *twice as slowly* for an address that did not exist ([F1](07-penetration-test.md)) | A defence that was itself the leak |
| A stale dev-server marker put the whole suite on output production never emits ([F8](07-penetration-test.md)) | Tests asserting against nothing |
| A failed query wrote its bindings — payload ciphertext, wrapped Item Key — into the log | Plumbing writing secrets where nobody looked |
| `HAVING` on a select alias: fine on SQLite, throws on Postgres | Two engines, one of them untested |

F1 is the one I think about. The decoy hash existed *specifically* to hide whether an account
exists, and because it was being generated on every request rather than cached, it made the
non-existent path cost two verifications against the real path's one. The mitigation was the
oracle. That is not a category of mistake I would have predicted.

### Enumeration was almost always the wrong shape

Four times this project reached for a list of dangerous things, and three of those were wrong:

- `dontFlash([...])` naming seven fields → **forget all flashed input**. The list had drifted so far
  that three entries named nothing in the application and three real credential fields had arrived
  without being added.
- "do not log these sensitive columns" → **never log any query binding**. A column added tomorrow is
  covered because nothing is exempt, rather than because somebody remembered.
- previewable file types → an **allow-list**, because `image/svg+xml` is an image and also a
  document that can run script, and `text/html` is the same problem with a different name.

The one enumeration that was right is `AuditMetadata::KEYS`, and the reason is instructive: it
*throws* on an undeclared key. A denylist fails open and a stale one reads exactly like a current
one; an allow-list that refuses the unknown case fails closed. The shape is not "list versus no
list", it is which way the default points when the list is out of date — and it will be out of date.

### Being confidently wrong in prose is easy, and looks exactly like being right

The worst thing I did on this project was write a mitigation into three documents that was
backwards. Typed secrets cluster payload sizes, so the padding bucket hints at an item's kind; I
wrote that each item was therefore written with its type's full key set, so items of one type differ
only by contents. That function did not exist, and the code did the opposite — and the code was
right. Uniform key sets *tighten* each type's size range, and tight ranges that differ from one
another are exactly what makes types separable.

Nobody would have caught it by reading, because it reads well. It took a question from outside
("is it worth removing `address`?") and twenty minutes of measurement. Dropping empty fields lets
eleven of twelve types produce a 128-byte payload; writing every key leaves eight. The numbers are
in [02 § Accepted leakage](02-threat-model.md#accepted-leakage) now, and the behaviour is pinned by
a test with its reasoning attached so nobody tidies it into uniformity.

The lesson is not "measure things". It is that a plausible security argument, written in a
confident register, next to code that does something else, is indistinguishable from documentation.

### Tests pass for the wrong reason far more often than they fail for the right one

This is the failure mode of a suite that grows for thirteen phases, and it happened repeatedly:

- **F8**, weeks of header and nonce assertions against tags nothing in production emits, because a
  stale `public/hot` had silently switched every render onto the Vite dev-server path.
- The leak canary sweeps logs and never caught the query-binding leak, because it only ever makes
  requests that are **rejected**. A well-formed request that fails *underneath* is a different code
  path, where the framework composes the log entry rather than the application.
- Writing the log-hygiene test itself: dropping the whole `secrets` table made the request fail
  during *validation*, so the only binding was a UUID and the test passed while proving nothing.
  Dropping one column was the difference between a real test and a decorative one.
- The Postgres `json`-versus-`jsonb` test would have passed under the type it exists to forbid, if
  its fixture had been canonical JSON. A canonical string survives `jsonb` by luck.

The countermeasure that actually works is the one the leak canary already used and I did not
generalise soon enough: **prove the danger is real in the same test file**. Assert that the thing
you are preventing would have happened. `LogHygieneTest` now builds the message the framework would
have written and asserts it contains the ciphertext, so the main assertion cannot decay into a
tautology without something going red.

### Coverage gates do not find blind spots

`resources/js/crypto/**` sits at 100% and has done since Phase 1. The log leak, F4, F8 and F11 all
lived comfortably alongside it. Coverage tells you which lines ran; it says nothing about which
situations you never thought to create.

### The prose was the highest-leverage artefact

The sweep that found two dropped work items found them because phases 5–11 each ended with a
"carried forward" section written in sentences, and phases 0–4 did not. Both gaps were in the
unaudited half. A task list with ticks cannot show you the clause that got dropped mid-sentence —
"and email notification", in task 9 of Phase 2, was simply never built and nothing recorded it.

---

## What I would do differently

**1. Run CI against Postgres from Phase 0.** It found a real bug within an hour of existing, and
thirteen phases of schema work had run only on SQLite — a database where a column type is close to
a comment, which is precisely the property that hides the `json`/`jsonb` question. This was the
cheapest thing on this list and it was done last.

**2. Write "carried forward" from Phase 0.** Free, and demonstrably the mechanism that catches what
a checklist cannot.

**3. Build the end-to-end suite early rather than scheduling it for Phase 11.** It still does not
exist. SR7 — key material never reaching browser storage — is verified by a source sweep and a trap
harness under Node, neither of which is a browser. That is honest, documented, and weaker than the
requirement deserves. Everything about the unlock state machine, the Worker lifecycle and the wipe
on lock would be better tested by a real page.

**4. Ship a field as load-bearing or not at all.** A secret's `type` was a five-value `<select>`
that changed nothing for thirteen phases. Worse, three of the five *promised* structure that was
not there: `card` offered one free-text box for a number, an expiry and a security code, and `key`
and `note` were unusable for their stated purpose because the only control in the application was a
single-line input. A field that lies about what it does is worse than a missing field, because
somebody organises their data around it.

**5. Start at envelope v2.** Version 1 put the header bytes outside the associated data, so a
downgrade attempt failed only because the tag happened not to verify under the other code path —
true, and accidental. Fixing it in Phase 10 means v1 must be read forever, because the server
cannot perform the migration that would retire it.

**6. Write the export in Phase 3.** It is the answer to "what happens if I want to leave", it is
what makes D3 defensible, and it took until Phase 12. It would also have forced the questions about
payload shape and unknown fields a lot earlier than the typed-secrets work did.

**7. Measure before writing the mitigation down, not after.** See above. The measurement took
twenty minutes; the wrong version sat in three documents for a phase and a half.

---

## What is still not true

The outstanding list, stated plainly rather than left for somebody to discover.

- **Nobody independent has reviewed any of this.** The penetration test in
  [07](07-penetration-test.md) was performed by the person who wrote the thing being tested, and
  F4 is the illustration of why that matters: it was found by a sweep, not by looking, because
  looking is exactly what misses the code you did not write.
- **The ZAP baseline has never run against a deployment.** The triage file is a set of predictions
  about what a spider makes of a client-rendered SPA.
- **There is no end-to-end suite**, so SR7's verification is a proxy for the real thing.
- **The phone Argon2id figure is an estimate.** 1.5–3 s is arithmetic from an M1 measurement, not a
  number from a device.
- **Nothing has been deployed or restored from a backup.** A backup you have not restored is a
  hypothesis, and `vault:verify-backup` finishes by saying that structure is all it checked.
- **Archived versions are permanently on envelope v1**, by design and without a route out.
- **No accessibility gate.** `eslint-plugin-vuejs-accessibility` would need a dependency decision
  that has not been made.

---

## The one that would keep me up

Adversary A3, and it is not fixable.

Everything in this project is real against a stolen database, a curious operator, a lost laptop, a
backup left on a disk, a member whose access was revoked, and a server that is honest but broken
into and read. None of it survives the server being taken over *while you are still using it*,
because the server ships the JavaScript that does the encryption. It can send you a copy that
captures your password as you type it, and your browser will run it exactly as it runs the real
one. No CSP, no integrity hash and no Worker boundary constrains the party that decides what the
rules are.

That is the honest ceiling on every browser-delivered encrypted application, and the useful thing
is not to pretend it away but to notice what it makes self-hosting *for*. Running the server
yourself does not remove A3. It moves it to somebody you already had to trust: you. Which is why
D11 scopes this to a small invited group on infrastructure its users control, and why the same
three uncomfortable sentences appear at `/security` in the product rather than only in this
repository.

---

## The comparison that started it

The 2017 version encrypted secrets at rest with a single application-wide key and decrypted them
on the server before rendering. Anybody with the database and the `.env` had everything. That was
one mistake, and it had total consequences.

This version has no mistake of that kind, and roughly a dozen smaller ones — most of which were
found, several of which are written up above with the reasoning that produced them, and at least
one of which (a mitigation documented backwards) survived review and needed a measurement to catch.

The difference between those two situations is the entire point. Not that the second one is free of
error, but that its errors are the kind a test can be written for, and that when one is found it
costs a fix rather than the whole database.
