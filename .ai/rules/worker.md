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
