---
paths:
  - 'resources/js/**'
---

# Js

## Key material stays in the Worker; nothing decrypted reaches the console
Key material lives only in the crypto Web Worker and in memory. Never `localStorage`, `sessionStorage`, IndexedDB, cookies, or Inertia page props (SR7).

Asserted by `resources/js/security.test.ts`: a source sweep with comments stripped, plus a full derive/seal/open run against traps on all four APIs. Neither is a browser, so an end-to-end suite is still the honest form — do not be the commit that makes the sweep start failing.

`no-console` is an ESLint error across resources/js. Disabling it inline is allowed but needs a comment explaining why the value is not sensitive. Same reasoning bans `v-html`: it is the shortest path from a decrypted payload to XSS.

The unlock state machine (anonymous → authenticated → unlocked → locked) wipes stores and terminates the Worker on lock. Anything caching decrypted data must subscribe to that.

## Trusted Types is enforced with no default policy — nothing may assign to innerHTML
The CSP ships `require-trusted-types-for 'script'` with `trusted-types vue`. There is deliberately no `default` policy: adding one that returns its input leaves the header in place and the protection gone.

So no source in resources/js may assign to innerHTML, outerHTML, insertAdjacentHTML, document.write, eval or new Function. Swept by resources/js/security.test.ts, which strips comments first.

Do not use Inertia's `<Head>` — it sets the title by assigning innerHTML on a template element, which throws on every navigation. Use `useDocumentTitle()` from @/lib/title. The progress bar and error dialog were replaced for the same reason by components/RequestChrome.vue; `progress: false` in app.ts must stay.
