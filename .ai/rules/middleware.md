---
paths:
  - app/Http/Middleware/SecurityHeaders.php
---

# Middleware

## Keep child-src beside worker-src or Safari blocks the crypto Worker
`child-src 'self'` is NOT a redundant duplicate of `worker-src 'self'`. Do not delete it.

WebKit does not implement `worker-src`. An unrecognised directive is ignored rather than honoured, so worker loading falls back to `child-src` and then to `default-src` — which is `'none'` here. Without `child-src`, Safari blocks the crypto Worker, and since every key lives inside it the app cannot decrypt anything.

Neither curl nor the Node test suite exercises the fallback chain; both see `worker-src` and are satisfied. Only a real WebKit browser catches it. Guarded by tests/Feature/SecurityHeadersTest.php.
