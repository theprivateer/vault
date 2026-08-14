# 02 — Threat Model

Written before implementation, deliberately. A design that cannot say what it protects against is
not a design. This document is also the thing a user should be able to read before trusting the
app, so it avoids euphemism.

## Assets

| Asset | Where it lives | Consequence of disclosure |
| --- | --- | --- |
| Secret payloads (credentials, notes, TOTP seeds) | Ciphertext at rest; plaintext in browser memory while unlocked | Total. This is the product. |
| File contents | Ciphertext in object storage; plaintext transiently in browser | Total for that file |
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
*Partially defended.* Server-side policies enforce roles and membership on every request. Vault
Key rotation on revocation (Phase 10) removes future access. **A revoked member keeps whatever
they decrypted before revocation** — unavoidable, logged, and stated in the UI.

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

## Accepted leakage

The server necessarily learns:

- **Graph shape** — how many vaults a user has, how many lockboxes per vault, how many secrets
  per lockbox, and which lockboxes link to which.
- **Timestamps** — creation, modification and access times, to the second. Activity patterns are
  visible: when you work, when you rotated something, when you panicked at 3am.
- **Sizes** — payload ciphertext length within AEAD overhead, and exact file sizes. A 2 KiB
  payload is a note; a 60-byte one is a password. Payloads are padded to a bucket size
  (Phase 4) to blunt this; files are not padded, and their sizes leak.
- **Membership** — who shares a vault with whom, and when access was granted or revoked. This is
  social-graph information and it is not hidden.
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

Testable statements. Phase 12 verifies each one against a running system.

| # | Requirement | Verified by |
| --- | --- | --- |
| SR1 | No plaintext secret material is ever written to the database, logs, cache, queue or object storage | Leak canary test (Phase 3), log scanning in CI |
| SR2 | No key capable of decrypting user content exists on the server, in any form, at any time | Code review; absence of any decrypt path; grep gate in CI |
| SR3 | Tampering with any stored ciphertext produces a visible, specific error — never silent corruption or a null | Crypto unit tests; the explicit inverse of the 2017 `DecryptException` bug |
| SR4 | A ciphertext cannot be moved between records or fields without detection | AAD binding tests |
| SR5 | Every request is authorised against vault membership and role, independently of client claims | Policy tests on every endpoint; an IDOR test suite |
| SR6 | Auth endpoints are rate limited per-IP and per-account, and do not reveal whether an account exists | Feature tests, including the pre-auth KDF-params endpoint |
| SR7 | Key material never reaches `localStorage`, `sessionStorage`, IndexedDB or a cookie | Storage assertions in E2E tests |
| SR8 | The audit log detects any insertion, deletion, reordering or modification of entries | Chain verification test with deliberate corruption |
| SR9 | Revoking a member rotates the Vault Key and re-wraps all item keys | Feature + E2E test |
| SR10 | The application sets a strict CSP with no `unsafe-inline` or `unsafe-eval` in `script-src` | Header assertion test in CI |
