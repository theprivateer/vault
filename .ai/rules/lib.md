---
paths:
  - 'resources/js/lib/**'
---

# Lib

## The client builds every AAD; the server never supplies one
Associated data is reconstructed in the browser from the record being held. The API sends ciphertext, UUIDs and version numbers — never AAD, and the client must never accept any.

A server that could name the AAD could serve one record's ciphertext with instructions to verify it against another, defeating the binding entirely (SR4).

Subjects: item payloads bind to the item's own UUID at `payload_version`; `item.key` binds to the item UUID at version 1; `vault.membership.key` binds to the **membership** UUID at version 1 — not the vault's, or a server could move one member's sealed key onto another's row. See docs/03 § Which subject, and which version.

Every write generates a fresh item key, on update as well as create.
