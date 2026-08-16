# 07 — Penetration Test

A self-directed test of the running application, worked through in Phase 11 and written up here
with every finding and its resolution. Scoped to OWASP Top 10 and the parts of ASVS L2 that apply
to a single-tenant, invite-only application with no public sign-up.

It is a self-test, and that is a real limitation rather than a modest one: the same person who
wrote a control is the worst person to decide it holds. What a self-test can do is be specific
about what was tried, what was found, and what was deliberately left — which is what the rest of
this document is.

## Method

Three passes, because they find different things.

1. **Reading the code against a list.** Each item on the checklist below was traced from the route
   table to the storage layer, rather than probed from outside. This is what found the timing
   divergences: they are invisible to a functional test and obvious in a diff.
2. **Sweeping the route table and the source tree.** Two of the findings — the exposed storage
   routes and the unlimited endpoints — are things nobody would look for, because nobody wrote
   them. The sweeps are now tests, so the next one shows up on its own.
3. **Measuring.** Response times on the pre-authentication endpoints, at the hash cost production
   uses.

Every finding below has a test beside its fix. That is the part that matters more than the fix: a
control with no test is a control that was true once.

## Findings

Severity is judged against this application's threat model rather than a generic scale, so
"account enumeration" ranks higher here than it would on a service with public sign-up — the
member list of a small invited group is closer to being a secret.

### F1 — Login answered twice as slowly for an address that did not exist

**Severity: medium. Fixed.**

The unknown-account branch generated its decoy hash on the spot, which meant a `Hash::make` *and*
a `Hash::check` against the real branch's single `Hash::check`. Two bcrypt rounds against one is
not a subtle difference — it is roughly double the response time, in a consistent direction,
requiring no statistics to read.

The intent was right and the implementation inverted it. The comment above the line said the decoy
existed so that a missing account would not "return measurably faster than a wrong password", and
it did not: it returned measurably *slower*, which identifies the account just as well.

Fixed by [`App\Support\DecoyHash`](../app/Support/DecoyHash.php), which generates one hash for the
deployment and caches it, so both branches perform exactly one verification. The decoy is resolved
before the branch rather than inside it, so both paths also pay the same lookup.

### F2 — Recovery did no hashing at all for an unknown address

**Severity: medium. Fixed.**

Worse than F1, and it sat directly beside it. The verification was an `&&` chain that reached
`Hash::check` only when a recovery wrapping existed, so an address nobody had returned in about a
millisecond where a real one spent tens. A cleaner oracle than the login form it was written to
match, in the flow that grants a session *without* a password.

Fixed the same way: one `Hash::check` on every path, against the stored verifier or the decoy.

### F3 — A backup code's position in the list was visible in the response time

**Severity: low. Fixed.**

The backup-code loop returned on the first match. Each iteration is a full password hash, so the
response time was a function of *which* code was submitted — measurable, and a small amount of
information about a credential that is otherwise never revealed. Every unused code is now checked
whichever one matches; there are at most ten, so the cost is bounded and constant.

### F4 — Two endpoints served the encrypted file store outside the authorisation model

**Severity: high. Fixed.**

`config/filesystems.php` carried the framework default `'serve' => true` on the `local` disk. That
disk is where every encrypted file chunk in the application lives, and the flag registers two
routes nobody in this repository wrote:

```
GET  /storage/{path}   storage.local
PUT  /storage/{path}   storage.local.upload
```

They read from and write to that directory without consulting a vault policy, a membership, or the
audit log. Both require a signed URL, so an attacker without the application key cannot use them —
which is a second line of defence, not a reason to leave the first one open. Nothing in this
application has ever generated such a URL: chunks are served by
[`FileChunkController`](../app/Http/Controllers/FileChunkController.php), which authorises every
request in its own right.

Found by the route sweep in `tests/Feature/RateLimitTest.php`, which noticed two endpoints with no
rate limit and, in explaining them, revealed that they should not exist. This is the finding that
justifies sweeping: it would never have surfaced in a review of the application's own code,
because it is not in the application's own code.

### F5 — Three DOM sinks were reachable, and Trusted Types was not enforced

**Severity: medium. Fixed.**

The CSP was strict — nonce-based, `strict-dynamic`, no `unsafe-inline` — but nothing stopped a
string being parsed as markup. Three assignments to `innerHTML` were reachable at runtime, all in
dependencies rather than in this application's code:

- Inertia's **progress bar**, built from a template string during application startup;
- Inertia's **error dialog**, built from the body of any response that comes back as HTML instead
  of a page — the one string you would least like a browser to parse;
- Inertia's **head manager**, which sets the page title by assigning an HTML string to a template
  element, on every navigation.

`require-trusted-types-for 'script'` with `trusted-types vue` is now enforced, and all three sinks
are gone rather than permitted: the progress bar and the failure notice are
[a component](../resources/js/components/RequestChrome.vue), and the title is set through
[`document.title`](../resources/js/lib/title.ts), which is not a Trusted Types sink at all.

The alternative — a default policy that returns its input — would have left the header in place
and the protection gone. There is deliberately no default policy, which is what makes the
directive mean anything.

### F6 — Most endpoints carried no rate limit

**Severity: low. Fixed.**

Five routes were throttled: login, registration, the KDF-params endpoints, the identity lookup and
the share-link reveal. The other forty-odd were not. Nothing there is guessable — a UUID is not
brute-forced at any rate — so this is not a guessing defence; it bounds how fast a session that has
*already* been stolen can empty a vault, which is the difference between a minute and a week.

Two limiters now cover everything, per account and per address, with a sweep asserting no route
escapes both. They are set generously enough that a chunked file upload does not trip them, because
a limit a real upload hits is a limit somebody turns off.

### F7 — The `Host` header was attacker-controlled input to URL generation

**Severity: low. Fixed.**

No trusted-hosts configuration, so `route()` built absolute URLs from whatever `Host` the request
carried — including the URL the login response hands to the browser to navigate to. The path to
exploiting it is narrow, since a victim's own browser sends the real host, and it widens as soon as
anything caches a response or puts a generated link in an email. `trustHosts()` is now configured
in `bootstrap/app.php`.

### F8 — The test suite was asserting against development output

**Severity: informational, and the most alarming thing here. Fixed.**

Not a vulnerability in the application; a hole in the evidence for it. `public/hot` is written by
`npm run dev` and removed when it stops cleanly, which it does not always do. A stale one from a
development session weeks earlier silently switched every page render in the suite onto the Vite
dev-server path — no manifest, no hashed filenames, no integrity attributes.

The assertions kept passing, against tags nothing in production emits. The header suite's own
docblock claimed it was asserted "against real Vite output", and it had not been for some time.
`tests/TestCase.php` now points the hot file at a path that cannot exist, so the suite renders from
the built manifest or fails.

The general lesson is worth more than the fix: a green test says the assertions ran, not that they
ran against the thing you meant.

### F9 — No subresource integrity on the bundle

**Severity: informational. Fixed, with a caveat that matters.**

Integrity hashes are now generated at build time and emitted on every script, stylesheet and
preload. Be clear about the size of it: the manifest lives on the same disk as the assets, so
anyone who can rewrite one can rewrite the other. This is not a defence against A3 and nothing in
a browser is. What it does defend against is a partial deploy, a cache serving a stale chunk
against a fresh manifest, and the day this stops being served from a single origin.

The crypto Worker — the one script where integrity would matter most — cannot carry a hash at all,
because the `Worker` constructor has no integrity option in any browser.

### F10 — No cross-origin embedder policy

**Severity: informational. Fixed.**

`COOP` and `CORP` were set; `COEP` was not. Every subresource here is our own, so `require-corp`
costs nothing and closes the document to anything embedded from elsewhere. Omitted while the Vite
dev server is running, since that serves modules cross-origin.

## The checklist, and what it did not find

Recorded because "we checked and it was fine" is information, and because the next person to look
should know which ground has been covered.

| Class | Result |
| --- | --- |
| **Broken access control / IDOR** | No finding. Every vault route carries `can:` middleware, which runs before the form request resolves — the ordering itself was a Phase 3 finding, since a controller-side check answered 302 for a real record and 404 for an unknown one, which is an existence oracle. Covered by `AuthorisationTest` and `RoleMatrixTest`. |
| **Mass assignment** | No finding. `Model::shouldBeStrict()` with guarding on, so an unexpected attribute throws rather than being silently dropped. Nothing takes a parent identifier from a request body — a lockbox is created inside a vault the router already resolved. |
| **SSRF** | Not applicable. The application makes no outbound HTTP requests of any kind: no HTTP client, no `curl`, no remote `file_get_contents`. URL fields exist only inside encrypted payloads the server cannot read, so there is nothing it could be persuaded to fetch. |
| **XSS** | No finding. Vue escapes interpolation, `v-html` is banned by lint, no source in `resources/js` assigns to a markup sink, and Trusted Types now enforces that at runtime. The page title is escaped by Inertia before it reaches `document.title`. Swept by `resources/js/security.test.ts`. |
| **CSRF** | No finding. Every write is an XHR carrying `X-XSRF-TOKEN`; there are no HTML form posts and no exemptions from the middleware. |
| **Session fixation** | No finding. The session is regenerated on both paths that establish one — password login and recovery — and invalidated with a fresh token on logout. |
| **Open redirect** | No finding. One redirect in the application, to a named route. No endpoint accepts a destination. |
| **Host header injection** | Finding F7. |
| **Timing** | Findings F1, F2, F3. Measurements below. |
| **Rate limiting** | Finding F6. |
| **Security headers** | Finding F10; F5 for Trusted Types; F9 for integrity. |
| **Dependencies** | No finding. `composer audit` and `npm audit --audit-level=moderate` both clean and both run in CI on every commit. The three `@noble` packages are now pinned to exact versions rather than caret ranges, so a routine install cannot float the primitives; everything else is caret-ranged and locked. TypeScript stays on 5.x deliberately ([ADR-0002](adr/0002-pin-typescript-5.md)). |
| **File upload** | No finding. Chunks are opaque ciphertext written to a random UUID path with no extension and never served with a content type; index bounds are enforced with `whereNumber` on the route and a check in the controller; each chunk's index and its file's chunk count are bound into the AEAD associated data, so truncation and reordering fail the tag rather than an application check. |
| **Audit integrity** | No finding. Chain verification, append-only enforcement and the daily external anchor were built and tested in Phase 7; nothing here weakened them. |
| **Error handling** | No finding. Exception reports and flashed input exclude every credential field. The failure notice that replaced Inertia's dialog deliberately shows a status code and not the response body. |

## Timing measurements

Medians of nine requests through the full HTTP stack on the development machine, after the fixes.
The absolute figures are hardware; the parity is the result.

| Endpoint | Address exists | Address does not | Hash operations |
| --- | --- | --- | --- |
| `POST /login` | 40.0 ms | 39.4 ms | 1 verification on both |
| `POST /recover` | 39.2 ms | 39.1 ms | 1 verification on both |
| `POST /auth/kdf-params` | 0.93 ms | 0.76 ms | none on either |
| `POST /recover/salt` | ~1 ms | ~1 ms | none on either |

For scale: one bcrypt verification at cost 12 measures **259 ms** on the same machine, so the
before-and-after is a difference of one whole verification. Before F1 was fixed, the unknown-account
path performed two of them and the known path one; before F2, the unknown path performed none and
the known path one.

`tests/Feature/Auth/TimingTest.php` asserts the operation counts rather than the clock. That is the
stronger of the two: a stopwatch says the difference was small on this machine on this run, and a
count says the two paths do the same work and fails the moment somebody adds a hash to one of them.

## Automated scanning

*Configured in CI; not yet run against a deployment.*

A ZAP baseline scan runs against a live instance on every commit — `php artisan serve` with the
real built bundle, so the headers under scan are the ones production sends. Findings are triaged
one line at a time in [`.zap/rules.tsv`](../.zap/rules.tsv), each with its reason.

The pre-triaged entries are predictions, made from knowing what this application looks like to a
spider: a client-rendered SPA with no HTML forms, whose CSRF token travels in a header the form
scanner cannot see. They will need revisiting after the first real run, and anything not on the
list has to be looked at rather than added.

## Residual risk, accepted

Not fixed, deliberately, with the reasoning rather than a shrug.

**A compromised server can serve modified JavaScript.** Adversary A3. Nothing here defends against
it and nothing in a browser could. It is now stated in the product itself at `/security`, in the
words a user would use, rather than only in this repository — which is the whole of D10.

**Decrypted names reach the browser tab.** A vault's or a lockbox's name becomes `document.title`,
so it appears in the tab, in the window title, and in the browser's own session history. That is
local to the user's device and never sent anywhere, and it is still plaintext outside the
application's control — visible in a screen share, in a screenshot, and to anything on the machine
that can read window titles. The alternative is a tab you cannot tell apart from any other tab.
Listed here rather than left unsaid.

**Timing residue on the second factor.** With TOTP enrolled, a correct password costs several more
hashes than a wrong one, because the second factor is only checked once the password verifies. That
makes "the password was right" observable to a stopwatch. Removing it means checking the second
factor for every attempt, which would make "this account has 2FA enabled" observable to anybody who
can name an address — a worse trade for a group this size. Bounded by the login limiter at five
attempts a minute per account and per address.

**The first request after a deployment.** `DecoyHash` generates its hash once and caches it, so the
very first login against an unknown address on a cold cache pays for a hash that no later one does.
One request per deployment, in the direction that errs slow.

**SR7 is tested outside a browser.** The storage sweep and the trap test run under Node, which
means they assert about the source and about the crypto client, not about a real page with a real
Worker. The honest form is an end-to-end suite, which does not exist yet.

## What this exercise cannot tell you

The controls verified here all sit above the cryptography. Nothing in this document establishes
that the key hierarchy is sound, that the envelope binds what it claims to, or that Argon2id is
being driven correctly — those are argued in [03](03-cryptographic-design.md), tested against RFC
vectors, and would be the subject of a review by somebody else.

And every finding above was found by the person who wrote the thing being tested. F4 is the useful
illustration: it was found by a sweep, not by looking, because looking is exactly what misses the
code you did not write.
