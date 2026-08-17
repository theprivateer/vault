---
paths:
  - 'resources/js/crypto/worker/**'
---

# Worker

## Worker test doubles must structuredClone, like a real postMessage
Any fake Worker in a test must `structuredClone(message)` before dispatching it. A fake that passes the object by reference accepts values a real `postMessage` refuses.

That gap shipped a `DataCloneError` to the browser with the whole suite green: Inertia page props are reactive, Vue reactivity is a `Proxy`, and a Proxy has none of the internal slots the structured clone algorithm needs. Registration, recovery and unlock were all broken.

`CryptoClient.send()` now normalises every request through `toCloneable()`, which reads through any wrapper and rebuilds plain data. Do not remove it, and do not bypass it by calling `postMessage` directly.

## Bulk opens never store an item key
`Keyring.openWithWrappedKey()` unwraps an Item Key, opens one payload and zeroises it in a `finally` — it is never stored under a handle. Nothing needs it again, because every write generates a fresh one; keeping them would mean a keyring that grows by one entry per secret ever displayed.

Use `client.openMany()` for anything more than a single item. Each `postMessage` is a structured clone plus a task-queue hop, and at a thousand secrets the crossings cost more than the XChaCha20 does. `lib/decrypt.ts` batches at `BATCH_SIZE`.

Per-item failures are returned inside the batch result, never thrown — one bad row must not blank out the batch it landed in.

## The Worker constructor is a Trusted Types sink and needs its named policy
`new Worker(url)` takes a **TrustedScriptURL**, not a string, under `require-trusted-types-for 'script'` — it is a way to make the browser fetch and run code. Without the policy the constructor throws and every page reports "encryption unavailable". This broke the first real deployment (docs/07 F12).

Two halves that must stay in step:
- `trusted-types 'vue vault-worker'` in `SecurityHeaders::BASE_DIRECTIVES`
- `workerScriptUrl()` in `crypto/worker/client.ts`, which creates the `vault-worker` policy once

**The policy accepts exactly one URL and throws on anything else.** Do not relax it to return its input — that is the `default` policy this design deliberately refuses, spelled differently. Do not add `allow-duplicates`.

Note the local `TrustedScriptUrl` brand: `@types/trusted-types` is not a dependency, and there is exactly one cast, at the constructor. Keep it to one.

Why no test caught it: the CSP drops Trusted Types entirely under the Vite dev server (the Vite client builds its error overlay from a string), so the shipped header is never applied in development or in the suite. Assume anything Trusted-Types-sensitive is untested until an E2E suite exists.
