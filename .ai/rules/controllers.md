---
paths:
  - app/Http/Controllers/SecretController.php
  - app/Http/Controllers/VaultRekeyController.php
  - app/Http/Controllers/FileChunkController.php
  - app/Http/Controllers/ShareLinkController.php
  - app/Http/Controllers/VaultOwnershipController.php
  - app/Http/Controllers/VaultController.php
  - app/Http/Controllers/IdentityRotationController.php
  - app/Http/Controllers/VaultResealController.php
  - app/Http/Controllers/AccountExportController.php
  - app/Http/Controllers/CryptoWorkerController.php
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

## A share token lives in the URL fragment and arrives in a request body, never a path
Never move the token to a route parameter (`/s/{token}`). A path segment is written to every reverse-proxy access log in the clear by default, and no application-level control can stop it — the requirement that no log holds a token is only achievable with the token in a POST body. Both the token and the link key live in the URL fragment, which browsers never transmit.

Which half goes where is load-bearing and easy to invert: the **creator** posts `token_hash`, so the server never holds a redeemable credential; the **recipient** posts the raw token and the server hashes it. Sending a hash at redemption instead would make the stored value the thing that opens a link, so any database reader could open every outstanding share.

Free consequence worth keeping: a chat client unfurling the link fetches `GET /s` with no fragment, so a link preview cannot consume a view. Redemption checks and increments inside one `lockForUpdate` transaction, and consumes the view *before* responding — a lost response burns the view, which is the correct direction to fail. Every unopenable state answers with the same 404. Guarded by tests/Feature/Vault/ShareLinkTest.php.

## Ownership transfer moves authorisation, never key material
Transfer requires the recipient to already be a live member at the current epoch with `accepted_at` set, because their membership row already holds the Vault Key sealed to them. So nothing is re-encrypted, `key_epoch` does not move, and the request carries no ciphertext — the only write in this app that carries none. Do not "improve" it by re-sealing or rotating: that is a different, much more expensive operation.

The outgoing owner is demoted to editor, never revoked. Revoking would delete the row holding their sealed key while they are still using the vault. It also unblocks leaving: `VaultMembershipPolicy::revoke` refuses to revoke any administrator, so before transfer existed the owner was immovable.

Vault + membership writes happen in one transaction with the vault row `lockForUpdate` and the actor's ownership re-checked inside it — the policy ran on a row read outside the transaction, and two administrators acting at once would otherwise produce two owner rows. Guarded by tests/Feature/Vault/OwnershipTest.php.

## A vault with other live members refuses to be deleted
`destroy()` throws a ValidationException when `Vault::otherLiveMembers()` is non-zero. A membership row *is* a sealed copy of the Vault Key, so deleting the vault under its other members withdraws their access via a route that never mentions access, and leaves none of the trail a revocation would. Hand the vault over or revoke them first.

Revoked rows are deliberately not counted — their access was already cut and the re-key that revocation demanded means their cached key opens nothing written since. Counting them would leave any vault that had ever been shared permanently undeletable.

A validation error rather than a 403, and this is a considered departure from the 404-not-403 rule in .ai/rules/policies.md: that rule stops strangers probing UUIDs, whereas here the caller is an authorised administrator being told about state. The policy still answers 404 to anyone who is not an administrator.

## Identity rotation is all-or-nothing, and the old private key is gone
The submission must cover every live membership of the caller — nothing missing, nothing extra. The old X25519 private key is discarded when this lands, so a membership left out is a sealed Vault Key with no surviving key to open it: that vault is permanently unreadable for that user, silently, with the request having reported success. Same failure mode as a partial vault re-key, same refusal. Revoked memberships are excluded; carrying them across would re-seal withdrawn access.

`accepted_at` is deliberately not cleared. Acceptance records that this user checked somebody *else's* fingerprint, and changing their own keys says nothing about that.

`rotation_payload` is stored byte-exact and must never be cast (same rule as `vault_memberships.grant_payload`). The server compares its fields against the row but does **not** verify the signature — it publishes the key it would check against, so it would only be checking its own work. Guarded by tests/Feature/Vault/IdentityRotationTest.php.

## A re-seal is not an edit, and needs its compare-and-swap
`previous_digest` is load-bearing. Each item carries the BLAKE2b digest of the ciphertext its plaintext was decrypted from, and the write applies only while the row still holds it. Without it, a tab that decrypted an hour ago writes hour-old plaintext back under a fresh envelope — well formed, correctly bound, genuinely freshly sealed, and wrong. Nothing downstream would catch it. A mismatched row is skipped, not refused: somebody wrote it, which puts it on the current version anyway.

The plaintext does not change, so nothing may behave as though it did — no version archived, `current_version` unmoved, `updated_at` untouched, one `vault.resealed` with a count rather than a run of `*.updated` entries. A false history in an append-only table cannot be corrected.

Deliberately **not** atomic, unlike the re-key: both envelope versions open, so each row is correct on its own and a half-finished pass leaves nothing to repair. That is what lets it batch and resume; do not "fix" it into an all-or-nothing submission.

`secret_versions` is absent from `ResealTarget` and must stay absent — an archive that could be rewritten is a rollback channel for a credential rotated because it leaked. Guarded by tests/Feature/Vault/ResealTest.php.

## The export endpoint is authorised by the shape of its query
There is no route parameter, so there is no `can:` middleware to attach — which makes this the one vault-reading endpoint whose authorisation lives entirely in how the query is written. It starts at the caller's live membership rows (same as VaultController::index), so a vault they have no row for cannot appear in the result. Never rewrite it as a `whereIn` over vault ids or a join from `vaults`: that moves the access decision from a relationship into a list somebody has to get right.

Trashed vaults, lockboxes and secrets are excluded. The 30-day grace period is a property of this server and a file on a USB stick cannot honour it, so an archive that reintroduced deleted credentials would be a surprise in the wrong direction.

`account.exported` is recorded *before* the response is built. Logging it after the bytes are out would make the widest read in the application the one read that can be made not to appear, by cutting the connection.

## The crypto Worker is served by the app, never from public/
A document sending `Cross-Origin-Embedder-Policy: require-corp` may only create a dedicated worker whose **own response** carries a compatible COEP. Same-origin is not enough — that inheritance rule is separate from the CORP check, which same-origin requests pass by default.

The Worker used to live in `public/build/`, so nginx served it and the middleware never saw it: no COEP, no CORP, no nosniff, no chosen Content-Type. The browser refused to load it and the whole application reported "encryption unavailable" (docs/07 F13).

So: `vite.worker.config.ts` builds to `storage/app/private/worker/`, and this controller serves it. **Do not move it back under `public/`, and do not fix a header problem here with an nginx `add_header`** — a server-config header is invisible to CI, cannot be asserted, and is gone on the next host. This was the second consecutive outage caused by something that ships but is never exercised.

`CryptoWorkerController::PATH` is the contract with the build config; if they disagree the route 404s and the symptom is identical to the outage. `vault:preflight` checks the file exists, because a deploy script running only `vite build` skips the worker.

Route is public (registration and login encrypt before auth) and rate-limited. Guarded by tests/Feature/CryptoWorkerTest.php.
