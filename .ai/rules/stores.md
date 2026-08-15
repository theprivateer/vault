---
paths:
  - 'resources/js/stores/**'
  - resources/js/stores/lock.ts
---

# Stores

## The decrypted store wipes on lock and fences in-flight work
`stores/vault.ts` is the only long-lived plaintext in the app. It subscribes to `onLock()` in `stores/session.ts`, not to a Vue watcher — a watcher fires next tick and "locked" has to mean the plaintext is already gone.

Every decrypt run captures a `generation` number. A run that was in flight when the lock happened resolves *after* the wipe, and writing its results in would silently repopulate a store that is meant to be empty. Check the generation before every write to state.

Opening a different vault wipes first, so a stale entry cannot surface in a search result for a vault the user has navigated away from.

Pinia is deliberately not used — the wiping and fencing are the hard parts and no store library does them.

## The lock signal lives in its own module to break an import cycle
`stores/lock.ts` holds only `onLock`/`notifyLock`. It is separate because `session.ts` loads the pins store on unlock while `pins.ts` and `vault.ts` subscribe to lock — together in one module that is a cycle, and not a stylistic one: subscribers call `onLock` during module evaluation, so whichever loaded second would reach a binding that does not exist yet and fail at start-up.

`session.ts` re-exports `onLock` so call sites still read as part of the session contract. Import it from either; do not move the registry back.
