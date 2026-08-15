---
paths:
  - app/Http/Controllers/SecretController.php
  - app/Http/Controllers/VaultRekeyController.php
  - app/Http/Controllers/FileChunkController.php
---

# Controllers

## Concurrent-edit conflicts are a validation error, never HTTP 409
Inertia reserves 409 for its own asset-version protocol and answers one with a hard page reload — which would throw away the user's unsaved edit while telling them nothing. Report the conflict with `ValidationException::withMessages()` instead.

`secrets.current_version` is the optimistic-concurrency token. Compare it inside the `where` clause of the update statement, never as a read followed by a write: a read-then-write leaves a window in which the other writer commits, and a concurrent edit is exactly the case being defended.

The server cannot merge two versions — they are ciphertext under different item keys — so the only options are refuse or lose one silently.

## A re-key is all or nothing, at exactly epoch+1
One request carries every item key and every remaining member's sealed vault key. It is accepted only if the epoch is exactly current+1 and the set matches the vault exactly — nothing missing, nothing extra. This is the fix for 2017's `vault:key`, which re-encrypted item by item and left mixed-epoch vaults when interrupted.

Three things that are easy to lose in a rewrite:
- The epoch is compared *after* `lockForUpdate`, never before. Two concurrent owners would otherwise both see epoch 3 and the second would overwrite the first.
- Trashed lockboxes and secrets are included. They hold item keys under the old Vault Key, and skipping them turns "restorable for 30 days" into "gone".
- Query-builder updates bypass the Ciphertext cast, so base64 is canonicalised by hand.

## A chunk whose bit is already set is a no-op that succeeds
`files.received_chunks` is a bitmap, one bit per chunk, not a counter. Chunk uploads are idempotent PUTs, so a client retrying one whose response it never saw would advance a counter twice and declare an incomplete file finished.

Writing a chunk whose bit is already set returns success and changes nothing. That single rule gives idempotency and makes a completed file immutable, and it is why `ciphertext_size` can be an addition rather than a delta.

The row is locked before the bitmap is read (as in VaultRekeyController) — two chunks completing at once would otherwise both read the same bitmap and the second write would erase the first's bit. `uploaded_at` is set in the same transaction that sets the last bit.

Quotas count stored ciphertext, including trashed files, never the plaintext size a client declares. A quota enforced against a claim is not a quota, and ignoring trashed rows would let a vault hold unbounded data by deleting and re-uploading.

## An archived version is a fresh encryption, never a copy of the column it replaced
The browser re-seals the outgoing payload under `secret.version.payload` at the version row's own UUID and posts it with the edit. Never make the server copy `secrets.payload_ct` into `secret_versions` — the copy carries associated data binding it to `secret.payload` at the secret's UUID, byte-for-byte the same binding the live column has, so any archived version could be written back over the live row and would verify. That is a silent rollback of a credential rotated *because* it leaked.

The four `version_*` fields are required on update, not optional: "writes append rather than overwrite" is only true if a write that does not append is refused. Consequence, and it is intended — a secret whose ciphertext no longer verifies cannot be edited, because nothing can archive what it could not read. Delete and re-add.

The archive is written inside the transaction that guards `current_version`, after the guarded update, so a write that loses the concurrency race leaves no orphan version behind. Guarded by tests/Feature/Vault/HistoryTest.php and resources/js/lib/history.test.ts.

## The re-key item set is every table holding a wrapped Item Key, including the invisible ones
`itemKeys()` must cover lockboxes, secrets, files AND secret_versions, trashed rows included. Files and archived versions are the easy ones to miss because neither appears on the page an owner is looking at when they rotate — and Phase 6 did miss files, which would have made every attachment in a re-keyed vault permanently unopenable while the request reported success.

The failure is silent in exactly the same way as skipping trashed rows: the client discards the old Vault Key, and nothing later can tell you which items were left behind. The server's defence is refusing an incomplete set, so anything gaining a `wrapped_item_key` column must be added here in the same commit. Caught by "the items nobody remembers" in tests/Feature/Vault/RekeyTest.php.
