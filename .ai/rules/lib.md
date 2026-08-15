---
paths:
  - 'resources/js/lib/**'
  - resources/js/lib/sharing.ts
  - resources/js/lib/files.ts
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
