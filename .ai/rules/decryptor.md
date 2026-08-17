---
paths:
  - 'resources/js/decryptor/**'
---

# Decryptor

## The decryptor is one file with its own CSP, built from crypto/ and never a copy of it
`npm run build:decryptor` inlines the bundle into public/build/vault-decryptor.html with a meta CSP of `default-src 'none'; script-src 'sha256-…'`. Both halves matter:

- `default-src 'none'` is why "this page cannot exfiltrate your secrets" is checkable by reading twenty lines instead of auditing a bundle. Never add connect-src, img-src or a font. If the page needs a network request, the design is wrong.
- The script is allowed by the hash of its own contents, computed at build time in vite.decryptor.config.ts. Editing the inlined script by hand produces a page that refuses to run — correct for a file whose job is handling plaintext.

It imports crypto/archive.ts rather than reimplementing the format. Do not write a second implementation "so the decryptor has no dependencies": the day it drifted would be the day somebody needed it. No framework and no external references, because this file has to work in a browser nobody has written yet, opened from a USB stick.

Argon2id blocks the main thread for ~4 s, so yield a frame before starting or the browser never paints the message explaining why it stopped responding. A Worker would need a second file or a blob URL, which is the one thing this page must not need.
