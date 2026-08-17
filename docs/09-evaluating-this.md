# 09 — Evaluating This Yourself

A walkthrough of the cryptographic design for somebody deciding whether to trust it with real
credentials.

[03](03-cryptographic-design.md) is the specification — organised by mechanism, written for
somebody implementing or reviewing. This is organised by *question*, and every claim it makes comes
with a way to check the claim rather than a request to believe it. Where something cannot be checked
from outside, it says so plainly, because a document like this that passes its own examination
perfectly is a document to be suspicious of.

---

## Three checks, ten minutes

If you do nothing else, do these. They are the ones that would catch the mistake this whole project
exists to avoid.

**1. Put a secret in and grep the database for it.**

```bash
composer setup
php artisan vault:invite you@example.com     # prints a single-use registration link
# register, unlock, and save a secret whose value is: hunter2-the-real-one

sqlite3 database/database.sqlite .dump | grep -c 'hunter2-the-real-one'   # local default
pg_dump "$DATABASE_URL"           | grep -c 'hunter2-the-real-one'        # a real deployment
```

Expect `0` from either. Then grep for the vault's name, the item's name, and its notes — all of them live
inside the ciphertext, not beside it. This runs automatically on every commit as the **leak
canary**: `tests/Feature/Vault/LeakCanaryTest.php` sweeps every table, every log file, the cache
store and the storage disk for a sentinel, and it sweeps for a *file's* name and contents too. It
also has a self-test, `sweeps the places it claims to sweep`, which plants a marker in each store
and fails if the sweep misses one — because a sweep that has quietly stopped looking somewhere is
indistinguishable from a clean result.

**2. Look for the decryption you were promised does not exist.**

```bash
grep -rn 'decrypt\|Crypt::\|openssl_decrypt\|sodium_crypto_.*_open' app/
```

You will find comments describing the rule and no calls. That is asserted properly by
`tests/Feature/NoServerDecryptionTest.php`, which tokenises the PHP and strips comments first — and
which contains `would catch a decryption call if one were added`, so the gate is proved to still
fire rather than assumed to. That test exists in the shape it does because the original was a shell
`grep` that flagged its own documentation and had to be rewritten.

**3. Read what the application says about itself.**

`/security`, reachable without signing in. If it reads as reassurance rather than description,
something has gone wrong with it — the point of that page is the part that is bad news.

---

## Following one password through the system

What happens when you type your master password, what the server learns at each step, and what
would have to be true for the step to be a lie.

### 1 — The password is stretched, in a Worker, and never leaves the tab

Argon2id at 64 MiB and three passes turns your password into 64 bytes of key material. It happens
in a dedicated Web Worker; the main thread holds opaque handles.

- **The server sees:** nothing. No request is made at this point.
- **Check:** `resources/js/security.test.ts` — `calls no storage API anywhere in the client`
  (a source sweep with comments stripped) and `writes nothing to storage while deriving, sealing and
  opening` (a full run against traps installed on `localStorage`, `sessionStorage`, IndexedDB and
  `document.cookie`). Neither is a browser, which is stated in
  [02 § Security requirements](02-threat-model.md) rather than glossed.
- **If this were false**, everything below is theatre. It is the load-bearing step.

### 2 — Those 64 bytes split into two keys that do different jobs

The first 32 bytes are a key-encryption key that never leaves the device. The second 32 are an
*auth key*, which is the only one the server ever sees — and only as a slow hash of it.

- **The server sees:** `argon2id(auth key)`. Proving who you are and being able to read your data
  are separate capabilities, which is what makes "there is no password reset" a consequence rather
  than a policy.
- **Check:** `resources/js/crypto/keys.ts`, and `crypto/keys.test.ts`.

### 3 — The KEK unwraps a random User Key

Your account has a random 32-byte User Key, stored wrapped by the KEK. Changing your password
re-wraps this one blob; it does not re-encrypt anything you own.

- **The server sees:** a wrapped blob it cannot open, on `user_key_wraps`.
- **Check:** the recovery kit is a second wrapping of the *same* User Key — which is why a kit works
  after a password change, and why losing both means the data is gone. `tests/Feature/Auth/RecoveryTest.php`.

### 4 — The User Key unwraps your identity keys

An X25519 pair for receiving sealed vault keys, and an Ed25519 pair for signing grants and audit
statements.

- **The server sees:** the public halves, and ciphertext for the private ones.
- **Check:** `resources/js/crypto/identity.ts`; fingerprints are recomputed from the public keys and
  never read from the server's `identity.fingerprint` column, which is a cache. Comparing two values
  the server supplied is asking the forger whether the forgery is genuine.

### 5 — Each vault has a Vault Key, sealed once per member

Sharing a vault means sealing its key to a member's X25519 public key and signing that grant with
Ed25519. Revoking means an atomic re-key at exactly `epoch + 1`.

- **The server sees:** who shares what with whom, and when. This is not hidden and is listed in
  [02 § Accepted leakage](02-threat-model.md#accepted-leakage).
- **Check:** `tests/Feature/Vault/SharingTest.php` and `RekeyTest.php`. The re-key is refused unless
  the submission covers *every* item key and *every* remaining member — a partial one would strand
  data unrecoverably while reporting success.

### 6 — Each item has its own Item Key, wrapped by the Vault Key

A vault, a lockbox, a secret, a file and an archived version each carry their own key.

- **Why it matters:** rotating a vault costs a re-wrap of 32-byte blobs rather than re-encrypting
  every payload. That is what makes rotation a routine operation instead of an emergency one.

### 7 — The payload is sealed, bound to the exact record it belongs to

One encrypted JSON object per item: name, value, notes, type, everything. The AEAD associated data
names the context, the record's UUID and the payload version.

- **The server sees:** ciphertext, a UUID, a version number, timestamps, and a *size bucket* —
  payloads are padded to a bucket size before sealing (powers of two up to 4 KiB, then a 4 KiB
  stride), so the stored length names a bucket rather than a character count.
- **Check:** `resources/js/crypto/aad.test.ts` and `crypto/envelope.test.ts`.

---

## What a hostile server would have to defeat

The more useful direction. For each attack: what stops it, and the test that says so.

| The server tries to… | What stops it | Where that is proved |
| --- | --- | --- |
| Serve one item's ciphertext in another item's place | AAD binds context + record UUID + version | `crypto/aad.test.ts`, and `CryptoInteropTest` — `rejects the envelope body when the associated data differs` |
| Alter a stored payload | Poly1305 tag | `crypto/envelope.test.ts` — `rejects every single-bit mutation`, which flips every bit of a sealed envelope in turn |
| Relabel a v2 envelope as v1 to get the weaker handling | v2 authenticates its own header bytes | `refuses a version 2 envelope relabelled as version 1` |
| Substitute its own public key when you share with somebody | Fingerprints recomputed locally, pinned on first use, and a changed pin is a hard stop with no one-click override | `tests/Feature/Vault/SharingTest.php`, `lib/pins.test.ts` |
| Claim a key rotation to explain a substituted key | The notice is signed by the key being *retired*, and it changes the warning's wording, never the verdict | `crypto/rotation.test.ts` |
| Write an old password back over a rotated one | An archived version is a fresh encryption bound to its own UUID, never a copy of the column it replaced | `tests/Feature/Vault/HistoryTest.php` |
| Truncate a file, or reorder its chunks | Each chunk's index **and its file's chunk count** are inside the AAD, and both come from the encrypted manifest | `crypto/chunks.test.ts` |
| Rewrite the audit log | A BLAKE2b chain, plus the head mailed daily to an address the server does not administer | `tests/Feature/Vault/AuditChainTest.php` |
| Invent an entry saying you revealed a secret | The two events the server cannot witness are signed by your Ed25519 key | `tests/Feature/Vault/AuditSignatureTest.php` |
| Read your data from a database backup | There is no key in it | The leak canary |
| **Serve you modified JavaScript** | **Nothing** | — |

That last row is not a gap in the table. It is the design's ceiling, and every honest version of
this document has to end its list there.

---

## What you cannot check from here

**That the code you are reading is the code being served.** Subresource integrity hashes live on the
same disk as the assets, so anyone who can rewrite one can rewrite the other. SRI defends against a
partial deploy, a stale cache and a second origin — not against the origin itself. This is adversary
A3, it is not defended, and it is stated in the product as well as here.

**That the primitives are correct.** This project tests that it *uses* them correctly, which is a
different claim. `resources/js/crypto/vectors.test.ts` checks X25519 (RFC 7748), Ed25519 (RFC 8032),
HKDF-SHA256 (RFC 5869), ChaCha20-Poly1305 (RFC 8439) and BLAKE2b-256 against published vectors;
Argon2id and the envelope layout are pinned to a committed fixture and cross-checked byte-for-byte
against PHP's `ext-sodium` in `resources/js/crypto/interop.test.ts` and
`tests/Feature/CryptoInteropTest.php`, which is what catches an encoding or endianness mistake that
would otherwise agree with itself in JavaScript. That the implementations are themselves sound rests
on `@noble`'s audits, not on anything here.

**That there is no side channel.** Timing on the authentication endpoints was measured and equalised
([07 § Timing](07-penetration-test.md#timing-measurements)), and one residue is documented and
accepted. Nothing has been measured about cache or power side channels in a browser.

**That the author has not fooled himself.** Nobody independent has reviewed this. The penetration
test was performed by the person who wrote the thing being tested, and
[08 § What surprised me](08-retrospective.md) records a case where a security argument was written
confidently into three documents while the code did the opposite — caught by a question from
outside, not by review.

---

## Questions worth asking of anything in this category

Generalisable, and more useful than any single answer below them.

1. **Can the operator reset your password?** If yes, they can reach your data, whatever the marketing
   says. There is no third option.
2. **What happens when you lose everything?** A truthful answer is bleak. A comforting one means
   somebody holds a key.
3. **Where does search happen?** Server-side search over encrypted data means either the server can
   read it, or there is a searchable-encryption scheme — which leaks a per-keyword equality oracle,
   and should be named rather than implied.
4. **Can you export, in a format something else can read?** If not, the encryption is also a lock-in
   mechanism.
5. **What opens the encrypted backup?** If the answer is "this product", it is not a backup.
6. **Is the threat model in the product, or only in the repository?** A threat model only its author
   reads is a document for people who were already going to trust it.
7. **Does it claim to defend against a compromised server?** If it is browser-delivered and it claims
   that, it is either wrong or not being straight with you.

## Where this one falls short of its own questions

Question 7 it answers honestly, and the answer is *no*. Questions 1–6 it answers well, and the
export in question 4 and the offline decryptor in question 5 both arrived in the last phase rather
than early, which is a criticism recorded in [08](08-retrospective.md).

Beyond the list: this has not been independently audited, has not been deployed, has never been
restored from a backup, and its browser-storage requirement is verified by a source sweep and a Node
harness rather than by a real page. The full outstanding list is
[08 § What is still not true](08-retrospective.md).

**Read the threat model before you trust it with anything you would mind losing.** That is not a
disclaimer bolted onto the end; it is the same sentence the README ends on and the honest summary of
everything above.
