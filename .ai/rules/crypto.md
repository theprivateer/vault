---
paths:
  - 'resources/js/crypto/**'
  - resources/js/crypto/padding.ts
  - resources/js/crypto/grant.ts
  - resources/js/crypto/chunks.ts
  - resources/js/crypto/audit.ts
  - resources/js/crypto/envelope.ts
  - resources/js/crypto/rotation.ts
---

# Crypto

## Crypto core: AAD is mandatory, decrypt throws, no app imports
Three rules, all load-bearing:

1. Every `seal()` call passes associated data built by `aad.ts` — context string, subject UUID, payload version. AAD is a required parameter with no default, so omitting it is a type error. Without it a malicious server can move a ciphertext between records or fields undetected (SR4).

2. Decryption failures throw `IntegrityError` and name the record. Never return null, never swallow. Returning null on a failed decrypt was the 2017 bug this project exists to fix (SR3).

3. This module must not import Vue, Inertia, or anything from the app — ESLint enforces it. It stays standalone and independently testable, with a 100% coverage gate in vitest.config.ts.

Spec: docs/03-cryptographic-design.md.

## Padding is what payload_version 2 means
Item payloads are padded to a bucket size (powers of two to 4 KiB, then a 4 KiB stride) inside the AEAD, so the padding is covered by the tag and a server cannot trim it back off to recover the real length.

There is no safe way to detect padding after the fact: an unpadded v1 payload run through `unpad` either throws or silently truncates a secret whose last byte was `0x80`. The reader is told by `payloadVersion` — bound into the AAD, so a server cannot relabel v2 as v1 to get the old handling.

v1 is read, never written. Do not drop it from `config/vault.php`'s `payload_versions` without a data migration; the server cannot perform one.

## Signing is domain-separated, and the Worker signs grants only
A self-signature, a grant and (from Phase 7) an audit entry are all Ed25519 signatures by the same key, so each carries a domain separator. `vault:grant:v1` for grants; without it one could be replayed as another.

The Worker's `signGrant` op takes a *grant*, not bytes, and applies the separator itself. Do not add a general "sign these bytes" operation: a signing oracle would let injected script obtain the user's signature on anything the format ever grows to cover, from one foothold.

`grant_payload` is stored as the exact bytes signed, so `parseGrant` must not re-canonicalise and compare — that would invalidate every signature the day the serialisation changes, which is the one thing storing exact bytes exists to prevent. Safety comes from the `v` version check plus comparing every meaningful field against the membership row.

## File chunks are AES-GCM with a counted nonce, and the AAD is what stops truncation
File bodies are the one exception to XChaCha20-Poly1305: AES-256-GCM via WebCrypto, because it is hardware-accelerated and a 100 MiB upload is the only place that matters. Keep the exception inside crypto/chunks.ts.

The nonce is `noncePrefix(8 random, per file) ‖ index(4 BE)`, not random. GCM's 96-bit nonce is too short to generate randomly, and a repeat under one key is a total break, not a degradation. It is derived rather than stored, so there is no nonce field a server could substitute.

Every chunk's AAD binds its index AND its file's chunk count. The count is what makes truncation fail the tag — with only the index, dropping the last chunk leaves every remaining one verifying. Both numbers must come from the encrypted manifest, never from the server's row.

A resume re-encrypts a chunk at a nonce it already used. That is safe only if the bytes are identical, so lib/files.ts verifies the source against the manifest's SHA-256 before sending anything. Never relax that check.

## The Worker signs statements, never bytes — and the vocabulary is the oracle
`AUDIT_ACTIONS` is closed for the same reason `signGrant` takes a grant rather than a buffer: these are signing oracles, and the set is the complete list of things injected script can make the user's Ed25519 key say. Adding an action widens that. Never add a general "sign these bytes" op.

Only events the server cannot witness belong here — currently `vault.unlocked` and `secret.revealed`. Anything the server observed needs no signature and gains nothing from one.

Domain separator `vault:audit:v1`, distinct from `vault:grant:v1`. Both are Ed25519 signatures by one key; without separation a signature over one could be presented as the other, and a grant is a statement about access.

`signed_payload` is stored verbatim and `parse` must never re-canonicalise and compare — that would invalidate every signature the day the format changes. Safety comes from the version check plus comparing the signed fields against the event being recorded.

Reporting is fire-and-forget and swallows failures on purpose (`lib/audit.ts`). A secret that was revealed was revealed; a failed report does not un-reveal it, and an error over a working feature teaches people to ignore errors.

## Envelope v2 authenticates its own header; v1 is still read
`seal` writes version 2, which appends `0x00 ‖ ver ‖ alg` to the associated data. In v1 those bytes sat outside it, so a downgrade failed only because the tag happened not to verify under the other code path — accidental rather than designed.

`open` accepts 1 and 2 and dispatches the AAD construction on the version byte it reads. That is safe *because* the tag then validates the choice: a v2 envelope relabelled v1 is opened with the v1 AAD and fails. Do not "harden" this by refusing to dispatch.

Never remove 1 from `Envelope::SUPPORTED_VERSIONS` (PHP) or `SUPPORTED_ENVELOPE_VERSIONS` (TS). There is no migration — the server cannot decrypt — so rows re-seal at v2 only when a client writes them, and a payload nobody edits stays on v1 forever. Dropping v1 makes those rows unreadable, and refuses the very write that would have upgraded them. `vault:health` counts them.

## A rotation certificate changes the wording, never the verdict
`checkIdentity` returns `certified: true` when the keys a peer pinned signed a notice introducing the new ones — and the status stays `changed`. There is no path to an accept, and there must not be: whoever stole the old key signs a perfectly valid notice, which is the case rotation most often exists for. Continuity of key is not continuity of person.

Order matters in `changed()`: recompute the fingerprint of the *retired* keys the server supplied and compare it against the local pin **before** verifying anything. Verifying a notice against a key the server chose is asking the forger whether the forgery is genuine.

Exactly one link is followed. Do not add a chain walk — a peer whose pin is two rotations stale has missed a conversation, and re-verifying out of band is the honest answer rather than a longer chain of the server's own assertions.

Signed by the key being *retired*. A notice signed by the incoming key attests only that the incoming key exists.
