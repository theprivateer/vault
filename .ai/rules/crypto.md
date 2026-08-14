---
paths:
  - 'resources/js/crypto/**'
---

# Crypto

## Crypto core: AAD is mandatory, decrypt throws, no app imports
Three rules, all load-bearing:

1. Every `seal()` call passes associated data built by `aad.ts` — context string, subject UUID, payload version. AAD is a required parameter with no default, so omitting it is a type error. Without it a malicious server can move a ciphertext between records or fields undetected (SR4).

2. Decryption failures throw `IntegrityError` and name the record. Never return null, never swallow. Returning null on a failed decrypt was the 2017 bug this project exists to fix (SR3).

3. This module must not import Vue, Inertia, or anything from the app — ESLint enforces it. It stays standalone and independently testable, with a 100% coverage gate in vitest.config.ts.

Spec: docs/03-cryptographic-design.md.
