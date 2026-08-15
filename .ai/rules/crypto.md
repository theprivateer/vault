---
paths:
  - 'resources/js/crypto/**'
  - resources/js/crypto/padding.ts
  - resources/js/crypto/grant.ts
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
