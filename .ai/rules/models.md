---
paths:
  - app/Models/VaultMembership.php
---

# Models

## grant_payload is stored byte-exact and must never be cast
`vault_memberships.grant_payload` holds the exact canonical JSON the granter's browser signed. A signature verifies over bytes, so it is stored as a raw string and deliberately has no `array` cast.

Adding one would decode on read and re-encode on write, and PHP's json_encode differs from the client's on escaping `/` and non-ASCII. Every such difference turns a valid grant into one no recipient can verify — and the failure looks exactly like tampering, which is the worst possible way for a bug to present.

Read it as a string; parse a copy if you need the fields. Guarded by "stores the grant payload byte for byte" in tests/Feature/Vault/SharingTest.php.
