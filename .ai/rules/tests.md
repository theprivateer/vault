---
paths:
  - 'tests/**'
---

# Tests

## The suite renders from the built manifest, never from a dev server
`tests/TestCase.php` points `Vite::useHotFile()` at a path that cannot exist. Do not remove it.

A stale `public/hot`, left behind by an `npm run dev` that did not stop cleanly, silently switched every page render in the suite onto the Vite dev-server path — no manifest, no hashed filenames, no integrity attributes. The header and nonce assertions kept passing against tags nothing in production emits, for weeks.

The cost is that assets must be built before the suite runs. CI and `composer setup` both do it.
