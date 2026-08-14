---
paths:
  - 'resources/js/pages/**'
---

# Pages

## Report the error you caught, never a guess about it
Use `describeError(cause, fallback)` from `@/lib/errors` in every catch. Never write a bare "something went wrong" string.

`no-console` is enforced across resources/js (deliberately — nothing downstream of a decrypt may be logged), so a generic message really is all anyone gets. Two debugging sessions have been lost to a catch that named key generation when the actual fault was a blocked Worker.

Crypto errors carry their own message and pass through unchanged. Anything else is reported with its type — a SecurityError means the CSP, a TypeError from fetch means the network, and the type is most of the diagnosis.

Where an operation has distinct phases (generate keys, then submit), catch them separately so the message names the phase that actually failed.
