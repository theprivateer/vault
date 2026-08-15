---
paths:
  - 'resources/js/**'
---

# Js

## Key material stays in the Worker; nothing decrypted reaches the console
Key material lives only in the crypto Web Worker and in memory. Never `localStorage`, `sessionStorage`, IndexedDB, cookies, or Inertia page props (SR7).

**No test asserts this yet** — the E2E suite that would is Phase 11. What holds today is that no code in `resources/js` calls any of those storage APIs at all, which is stronger than a convention and weaker than a test. Do not be the commit that makes it false.

`no-console` is an ESLint error across resources/js. Disabling it inline is allowed but needs a comment explaining why the value is not sensitive. Same reasoning bans `v-html`: it is the shortest path from a decrypted payload to XSS.

The unlock state machine (anonymous → authenticated → unlocked → locked) wipes stores and terminates the Worker on lock. Anything caching decrypted data must subscribe to that.
