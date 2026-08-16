# 02 — Threat Model

Written before implementation, deliberately. A design that cannot say what it protects against is
not a design. This document is also the thing a user should be able to read before trusting the
app, so it avoids euphemism.

## Assets

| Asset | Where it lives | Consequence of disclosure |
| --- | --- | --- |
| Secret payloads (credentials, notes, TOTP seeds) | Ciphertext at rest; plaintext in browser memory while unlocked | Total. This is the product. |
| File contents | Ciphertext in object storage; plaintext transiently in browser | Total for that file |
| Superseded secret payloads | Ciphertext at rest, each under its own Item Key | Total for the values they held — including one rotated *because* it leaked |
| Share link keys and tokens | Only in a URL fragment, never on the server | Whoever holds the link holds the secret it carries |
| TOTP seeds | Inside `payload_ct`, like any other field | Ongoing ability to produce valid codes for that account |
| Vault Keys, Item Keys | Wrapped at rest; plaintext in browser memory while unlocked | Disclosure of everything they protect |
| User Key, KEK, master password | Derived in browser; never at rest, never transmitted | Total compromise of that account, all vaults |
| Recovery code | Shown once; user's responsibility thereafter | Equivalent to the password |
| Auth key | Transmitted on login; slow hash stored server-side | Allows authentication, **not** decryption |
| Private keys (X25519, Ed25519) | Encrypted under User Key | Ability to receive future grants; forge grants |
| Structural metadata (graph shape, timestamps, sizes) | Plaintext, by necessity | Traffic analysis — see [Accepted leakage](#accepted-leakage) |
| Audit log | Plaintext, hash-chained | Reveals access patterns; tampering hides an intrusion |
| Session cookie | Browser, `HttpOnly` `Secure` `SameSite=Strict` | Account access while unlocked; not decryption capability |

## Adversaries

**A1 — Passive database compromise.** Stolen backup, leaked dump, subpoenaed snapshot, a
misconfigured replica. Has all ciphertext and all wrapped keys, offline and indefinitely.
*Defended.* Everything of value is AEAD ciphertext under keys that are nowhere in the dump. The
best available attack is an offline guess of a user's password against their Argon2id-wrapped
User Key, at 64 MiB and 3 passes per guess.

**A2 — Compromised server at rest.** Root on the box, reading files, memory, environment and the
database, but not modifying the served frontend.
*Defended.* There is no `VAULT_KEY` to steal — this is the specific failure of the 2017 design
that D1 removes. The attacker sees ciphertext flowing past and learns metadata (A6).

**A3 — Malicious or compromised server actively serving code.** Modifies the JavaScript bundle to
exfiltrate the master key on next unlock.
**NOT DEFENDED. This is the fundamental limit of browser-delivered end-to-end encryption, and it
must be stated in the product UI, not only here.** Mitigations reduce the odds of an *incidental*
compromise becoming a crypto compromise — strict CSP so injected script cannot execute or phone
home, SRI so a modified bundle fails to load, `connect-src 'self'` so exfiltration has nowhere
obvious to go, and key material held in a Web Worker so main-thread script cannot read it
directly. None of these defend against the party that legitimately controls the served bundle.
The honest mitigations are operational: minimal server attack surface, signed and reviewed
deploys, and the future work in D10.

**A4 — Network attacker.** MITM, hostile Wi-Fi, rogue CA.
*Defended.* TLS 1.3, HSTS with preload, and the payload is already ciphertext. A successful TLS
MITM degenerates to A3.

**A5 — Malicious authenticated user (a vault member).** A Viewer trying to write; a member trying
to reach a vault they were never granted; a revoked member trying to retain access.
*Partially defended.* Server-side policies enforce roles and membership on every request, and a
revoked membership stops being one on the *next request* — before any re-key has happened. Vault
Key rotation then removes future access to new ciphertext (built in Phase 5; made routine in
Phase 10). **A revoked member keeps whatever they decrypted before revocation** — unavoidable,
logged, and stated in the UI.

**A6 — Metadata analyst.** Anyone with database or log access, inferring from what is necessarily
plaintext.
*Partially defended; see [Accepted leakage](#accepted-leakage).*

**A7 — XSS in the frontend.** Injected script running in the origin while the vault is unlocked.
*Partially defended.* Strict CSP with nonces and `strict-dynamic` is the primary control; Vue's
default escaping and a ban on `v-html` are the second; Trusted Types the third. Holding key
material in a Web Worker means injected main-thread script cannot read the User Key — it can ask
the worker to decrypt specific items, which is bad, but it is bounded, slower, and visible in the
audit log. Auto-lock bounds the window.

**A8 — Local attacker on an unlocked device.** Someone at the keyboard, or malware on the client.
*Not defended, by definition* — but bounded: idle auto-lock, lock on tab hide (configurable), no
key material in `localStorage`/`sessionStorage`/IndexedDB, clipboard clearing, and re-auth
prompts before destructive actions.

**A9 — Phishing.** A convincing clone harvesting the master password.
*Weakly defended.* Password managers and browser autofill help; the recovery kit is never
requested by the real app after signup, which is stated in the UI. WebAuthn as a second factor
would help materially and is deferred, not dismissed.

**A10 — Supply chain.** A malicious version of a dependency.
*Partially defended.* Lockfiles committed, `npm audit` / `composer audit` in CI, Dependabot with
review, and a deliberately small crypto dependency surface — three `@noble` packages, all
audited, all pure TypeScript, no post-install scripts, no transitive dependencies. This is a
significant reason for choosing them.

This entry has been paid for at least twice. TOTP is thirty lines of specified arithmetic here
rather than a package, in both PHP and TypeScript. And `zxcvbn-ts`, which
[05](05-implementation-plan.md#phase-9--totp-generators--one-time-links) named for password strength
estimation, was declined in favour of a smaller in-house estimator: three packages and several
hundred kilobytes of dictionaries is a poor trade for a progress bar. The cost is real and is stated
where a user can see it — the meter says outright that it carries no dictionary and will overrate a
word or a name.

## Accepted leakage

The server necessarily learns:

- **Graph shape** — how many vaults a user has, how many lockboxes per vault, how many secrets
  per lockbox, and which lockboxes link to which.
- **Timestamps** — creation, modification and access times, to the second. Activity patterns are
  visible: when you work, when you rotated something, when you panicked at 3am. The audit log
  (Phase 7) records this deliberately and in more detail — every action, its actor and its subject
  — because being able to answer *what happened* is the main compensating control for a server that
  cannot see *what is in* anything. What it never records is content: `audit_events.metadata` takes
  only keys from a closed, declared set, none of which can differ between two users doing the same
  thing to different data. Addresses are stored as `HMAC(APP_KEY, ip)` rather than in the clear:
  correlatable, not reversible by whoever ends up with the database alone.
- **Sizes** — which *bucket* a payload falls into, and exact file sizes. Payloads are padded to a
  bucket before encryption (powers of two to 4 KiB, then a 4 KiB stride), so the stored length no
  longer tracks the length of the secret: a 1-character password and a 12-character one are
  stored at identical size. What remains is the bucket, so a 3 KiB note is still visibly larger
  than a credential. Padding to one fixed size would close it completely and would make every
  password cost as much to store as a document; the buckets are the compromise. Files are not
  padded, and their sizes leak: `files.chunk_count` gives the size to within a chunk on its own,
  and `ciphertext_size` gives it to the byte. Padding a 100 MiB upload to a bucket would mean
  storing and transferring an arbitrary amount of nothing, and the cost is real where a payload's
  is not. A file's *name*, type and hash are all inside its encrypted manifest, so what leaks is
  how big something is, never what it is.
- **History** — how many superseded payloads each secret has, when each was archived, and who made
  the edit. A version's contents are sealed under their own Item Key like anything else, so what
  leaks is that a value changed on a given day, never what it changed from. A vault's retention
  policy is plaintext too (`vaults.history_max_versions`, `history_max_age_days`), because the
  server is the thing that enforces it — a policy only the client could read would be a policy
  nothing applies. Retention is also the one control here that reduces what a *future* database
  theft yields: nobody who could read the versions is stopped by deleting them, but bytes that no
  longer exist cannot be stolen next year.
- **Key age and rotation history** — when a vault's key last changed (`vaults.key_rotated_at`), how
  often its owner asked to be reminded, and the fact and date of every identity rotation a user has
  performed. The rotation dates are inherent rather than conceded: serving a different public key
  announces the change, and the signed notice beside it has to name a date to be worth anything to
  the peer reading it. What leaks is that somebody replaced their keys on a Tuesday, never why.
- **KDF parameters** — each account's Argon2id settings, which have to be readable before
  authentication for the client to derive anything at all. They say how well a given password is
  protected, which is the closest this schema comes to a "weak account" signal — mitigated by the
  parameters being a per-deployment default that upgrades silently rather than a per-user choice.
- **Membership** — who shares a vault with whom, with what role, and when access was granted or
  revoked. This is social-graph information and it is not hidden. Two parts of it are visible
  because they have to be: `grant_payload` is plaintext, since the recipient must read the bytes
  their signature covers, and it names the vault, the recipient, the role and the key epoch; and
  a `key_epoch` that advances tells the server a vault was re-keyed, which usually means somebody
  was removed. The one thing that is *not* visible is who a user has verified out of band — the
  pin store is encrypted under the User Key, because a server that could read it would know which
  key substitutions would go unnoticed, and one that could write it could mark its own key as
  already trusted.
- **Share links** — that a link exists, when it was created and by whom, when it expires, how many
  times it may be opened and how many times it has been, and which secret it came from. What is not
  visible is the token or the link key: both live in the URL fragment, which no browser transmits,
  and the server holds only `BLAKE2b(token)` and a payload sealed under a key it has never seen.
  The token reaching the server only in a request body rather than a path segment is what keeps it
  out of access logs — a requirement no application-level control could satisfy if the token were in
  the request line. A link's *opening* is recorded with no actor, because there is none: the
  recipient has no account, and all that is known of them is a keyed hash of their address.
- **Handles** — the identity directory confirms whether a handle exists to any signed-in user.
  Sharing by handle requires exactly that lookup, and D11 scopes the system to a small invited
  group where the member list is not the secret.
- **Access patterns** — which item was fetched and when, from the request log and audit log.
- **IP addresses and user agents** — in web server logs. Application logs store a salted hash of
  the IP rather than the address itself.

**Not accepted, and therefore encrypted:** every name, title, description, note, username,
password, URL, TOTP seed, filename and file body, and the *type* of every secret.

## Trust assumptions

Stated so they can be challenged:

1. The user's device, browser and OS are not compromised (A8).
2. The served JavaScript is the JavaScript we published (A3) — the weakest assumption here.
3. `@noble/*`, PHP's `ext-sodium` and the browser's WebCrypto implement their primitives
   correctly.
4. `crypto.getRandomValues()` is a sound CSPRNG.
5. TLS provides transport confidentiality and server authentication.
6. The user's master password has meaningful entropy, and their recovery kit is stored somewhere
   an attacker is not.

## Security requirements

Testable statements. Phase 11 closes the gaps below and Phase 12 verifies each one against a
running system. **Where a requirement has no automated test yet, it says so** — a requirement
listed as verified when it is not is worse than one listed as outstanding, because it reads as
evidence.

| # | Requirement | Verified by |
| --- | --- | --- |
| SR1 | No plaintext secret material is ever written to the database, logs, cache, queue or object storage | `tests/Feature/Vault/LeakCanaryTest.php` — two sentinels, a vacuous-pass guard and a self-test |
| SR2 | No key capable of decrypting user content exists on the server, in any form, at any time | `tests/Feature/NoServerDecryptionTest.php`, run again as its own CI job |
| SR3 | Tampering with any stored ciphertext produces a visible, specific error — never silent corruption or a null | `crypto/envelope.test.ts` — every single-bit mutation of a short envelope throws |
| SR4 | A ciphertext cannot be moved between records or fields without detection | `crypto/aad.test.ts`, `crypto/keys.test.ts`, and `lib/history.test.ts` for the case history creates — an archived version offered as the live payload |
| SR5 | Every request is authorised against vault membership and role, independently of client claims | `tests/Feature/Vault/AuthorisationTest.php` (IDOR) and `RoleMatrixTest.php` (role × action) |
| SR6 | Auth endpoints are rate limited per-IP and per-account, and do not reveal whether an account exists | `tests/Feature/Auth/LoginTest.php`, `RecoveryTest.php` — including the pre-auth salt endpoints |
| SR7 | Key material never reaches `localStorage`, `sessionStorage`, IndexedDB or a cookie | **Not yet automated.** Holds by construction — nothing in `resources/js` calls any of those APIs — but construction is not a test. Needs the Phase 11 E2E suite |
| SR8 | The audit log detects any insertion, deletion, reordering or modification of entries | `tests/Feature/Vault/AuditChainTest.php` — one deliberate-corruption case per kind, plus truncation from the end and a rewritten head, which the chain alone cannot catch. `AuditSignatureTest.php` covers a fabricated entry whose hashes were recomputed |
| SR9 | Revoking a member rotates the Vault Key and re-wraps all item keys | `tests/Feature/Vault/RekeyTest.php`, `SharingTest.php` |
| SR10 | The application sets a strict CSP with no `unsafe-inline` or `unsafe-eval` in `script-src` | `tests/Feature/SecurityHeadersTest.php`, asserted against real Vite output |
| SR11 | A one-time share link opens the number of times it was allowed to and no more, and neither its token nor its key is ever written to a database row or a log | `tests/Feature/Vault/ShareLinkTest.php` — the count is consumed inside a locked transaction, and a sweep over every table and log file looks for both halves of the credential |
