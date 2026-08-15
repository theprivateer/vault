---
paths:
  - 'resources/js/stores/**'
---

# Stores

## The decrypted store wipes on lock and fences in-flight work
`stores/vault.ts` is the only long-lived plaintext in the app. It subscribes to `onLock()` in `stores/session.ts`, not to a Vue watcher — a watcher fires next tick and "locked" has to mean the plaintext is already gone.

Every decrypt run captures a `generation` number. A run that was in flight when the lock happened resolves *after* the wipe, and writing its results in would silently repopulate a store that is meant to be empty. Check the generation before every write to state.

Opening a different vault wipes first, so a stale entry cannot surface in a search result for a vault the user has navigated away from.

Pinia is deliberately not used — the wiping and fencing are the hard parts and no store library does them.
