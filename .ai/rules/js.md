---
paths:
  - 'resources/js/**'
  - resources/js/app.ts
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

## Never pass a `title` callback to createInertiaApp
Inertia's head manager calls the `title` callback with an EMPTY STRING to decide whether it owns a title element. Anything truthy comes back as `<title data-inertia="">…</title>`, which its renderer then builds via `template.innerHTML` — on start-up and on every navigation. Under `require-trusted-types-for 'script'` that throws and the app does not start.

With no callback, `collect()` returns nothing and the renderer is never reached. The suffix rule lives in `lib/title.ts`, which assigns `document.title` — a plain string property, not a sink.

This shipped and broke the first real deployment (docs/07 F12). It survived because the sink is inside a dependency, which `security.test.ts` cannot sweep, and because the CSP drops Trusted Types under the Vite dev server so no test environment ever applied the shipped header.

Same reason `progress: false` stays, and `<Head>` is banned. Inertia has five sink assignments: two in the error modal (suppressed via `preventDefault()` on `httpException`/`networkError` in RequestChrome.vue), one in the progress bar, two in the head manager. All five must stay unreachable.

Guarded by `security.test.ts` — "gives Inertia no title callback".
