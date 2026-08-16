---
paths:
  - 'config/**'
---

# Config

## The local disk must keep serve => false
`config/filesystems.php` sets `'serve' => false` on the `local` disk, which holds every encrypted file chunk. The framework default of `true` registers `GET` and `PUT /storage/{path}` — routes that read and write that directory outside the vault policies, outside the membership checks and outside the audit log. They need a signed URL, which is a second line and not a reason to open the first.

Nothing here ever generates such a URL: chunks go through FileChunkController, which authorises each request. Found in Phase 11 (docs/07-penetration-test.md F4).
