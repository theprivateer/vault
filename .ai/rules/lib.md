---
paths:
  - 'resources/js/lib/**'
  - resources/js/lib/sharing.ts
  - resources/js/lib/files.ts
  - resources/js/lib/generate.ts
  - resources/js/lib/secretTypes.ts
---

# Lib

## The client builds every AAD; the server never supplies one
Associated data is reconstructed in the browser from the record being held. The API sends ciphertext, UUIDs and version numbers — never AAD, and the client must never accept any.

A server that could name the AAD could serve one record's ciphertext with instructions to verify it against another, defeating the binding entirely (SR4).

Subjects: item payloads bind to the item's own UUID at `payload_version`; `item.key` binds to the item UUID at version 1; `vault.membership.key` binds to the **membership** UUID at version 1 — not the vault's, or a server could move one member's sealed key onto another's row. See docs/03 § Which subject, and which version.

Every write generates a fresh item key, on update as well as create.

## Never trust the server's fingerprint, and never verify against its key
Fingerprints are recomputed from the public keys, never read from `identity.fingerprint` — that column is a cache, and a server substituting a key would substitute the fingerprint beside it, so comparing the two served values agrees with itself.

A grant is verified against the granter's *pinned* key. Verifying against the key the server just sent is asking the forger whether the forgery is genuine.

Verifying a grant is two checks: the signature, and then the signed fields against the membership row. A valid signature over *some* grant is not evidence about *this* row — a server holding any genuine grant could otherwise staple it to a fabricated membership with a role of its choosing.

A changed pin is a hard stop with no one-click override. Re-verifying is a separate, deliberate action.

## Decrypted content never keeps a live object URL
An object URL is a live handle to decrypted bytes that anything on the page can fetch, and one left behind outlives a lock — the store is wiped and the Worker terminated while the plaintext stays reachable at a `blob:` URL.

Use `withObjectUrl(blob, use)`, which revokes in a `finally`. The one exception is an `<img>` preview, which needs the handle until it decodes: revoke on `load`, on close, on unmount, and on `onLock`.

Previews are an allow-list (`isPreviewable`), never a block-list. `image/svg+xml` is an image and also a document that can run script; `text/html` is the same problem with a different name.

## Generated entropy is arithmetic; typed-password strength is a guess, and the UI must say which
`generate.ts` reports `log2(alphabet) × length` as exact, which is only true because every draw uses rejection sampling from `crypto.getRandomValues`. Never replace `uniformIndex` with `random % n` — the bias silently shaves real entropy below the number displayed beside it, which is the one figure the user is being asked to trust. `generate.test.ts` guards this with a chi-squared test (61 df, threshold 150; a modulo bias scores over 800). Per-count bounds were tried first and were flaky at any useful width.

Do not add "at least one of each class" post-processing: it removes valid outputs while the reported figure keeps describing the unsampled space. Capitalising adds no entropy either, and the code says so.

`strength.ts` is deliberately weaker than zxcvbn — that dependency was declined for A10, with the user's approval. It has no dictionary and overrates words, names and l33t-speak. The meter states that on screen and the tests pin it as a property, so it is not rediscovered as a bug. If a dictionary is ever added, that wording has to change with it.

The EFF wordlist is bundled, never fetched: the CSP forbids it, and asking a CDN for a wordlist tells a third party when somebody is creating a credential. `assertWordlistIntact()` checks the count the entropy arithmetic assumes.

## Secret types are one declarative table — never hand-render a type
Twelve types share one form builder, one row renderer, one share renderer and one diff, all reading SECRET_TYPES. Adding a type is a row of data. Do not add a bespoke form block or `v-if="type === 'card'"` anywhere — that reintroduces the per-type path from a decrypted field to the DOM that this table exists to remove.

Two invariants, asserted as loops in secretTypes.test.ts:
- A field is `sensitive` or `indexable`, never both. Masked = it authenticates; indexable = somebody types it to find the item.
- `indexable` defaults to false. Identifiers and locators opt in (username, host, email, cardholder, city); anything credential-shaped cannot become searchable by accident.

`isSensitive` is asked per type, never per key — `value` is a password on a login and plain text on a text item. Unknown type or unknown field ⇒ treated as sensitive.

`unmappedFields` must keep working: old payloads (every `card` written when cards were one `value` box) and payloads from later builds have to render, and the form carries them through an edit untouched. Dropping what you cannot display turns "we can't show this" into "this is gone".

Padding note: fixed field sets cluster serialised sizes, so the bucket now hints at an item's kind. Recorded in docs/02 § Accepted leakage. Keep writing the type's full key set so items of one type differ only by contents.
