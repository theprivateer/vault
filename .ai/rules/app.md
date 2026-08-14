---
paths:
  - 'app/**'
---

# App

## The server must never be able to decrypt user content
This is a zero-knowledge app. Secrets, names, notes and filenames arrive as opaque ciphertext blobs and are stored as-is.

Never add a decryption path in app/: no `decrypt()`, no `Crypt::`, no `openssl_decrypt`, no `sodium_crypto_*_open`. CI greps for these and fails the build (SR2 in docs/02-threat-model.md).

Validate ciphertext for shape and size only — never parse a payload. If a feature seems to need server-side plaintext (search, email a secret, server-rendered display), the answer is no, not "add an escrow key". See docs/adr/0001-zero-knowledge-architecture.md.
