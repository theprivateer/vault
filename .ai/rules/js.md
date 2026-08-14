---
paths:
  - 'resources/js/**'
---

# Js

## Key material stays in the Worker; nothing decrypted reaches the console
Key material lives only in the crypto Web Worker and in memory. Never `localStorage`, `sessionStorage`, IndexedDB, cookies, or Inertia page props — an E2E test asserts this (SR7).

`no-console` is an ESLint error across resources/js. Disabling it inline is allowed but needs a comment explaining why the value is not sensitive. Same reasoning bans `v-html`: it is the shortest path from a decrypted payload to XSS.

The unlock state machine (anonymous → authenticated → unlocked → locked) wipes stores and terminates the Worker on lock. Anything caching decrypted data must subscribe to that.
