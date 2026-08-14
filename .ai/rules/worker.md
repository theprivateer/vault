---
paths:
  - 'resources/js/crypto/worker/**'
---

# Worker

## Worker test doubles must structuredClone, like a real postMessage
Any fake Worker in a test must `structuredClone(message)` before dispatching it. A fake that passes the object by reference accepts values a real `postMessage` refuses.

That gap shipped a `DataCloneError` to the browser with the whole suite green: Inertia page props are reactive, Vue reactivity is a `Proxy`, and a Proxy has none of the internal slots the structured clone algorithm needs. Registration, recovery and unlock were all broken.

`CryptoClient.send()` now normalises every request through `toCloneable()`, which reads through any wrapper and rebuilds plain data. Do not remove it, and do not bypass it by calling `postMessage` directly.
