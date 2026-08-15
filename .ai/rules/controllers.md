---
paths:
  - app/Http/Controllers/SecretController.php
---

# Controllers

## Concurrent-edit conflicts are a validation error, never HTTP 409
Inertia reserves 409 for its own asset-version protocol and answers one with a hard page reload — which would throw away the user's unsaved edit while telling them nothing. Report the conflict with `ValidationException::withMessages()` instead.

`secrets.current_version` is the optimistic-concurrency token. Compare it inside the `where` clause of the update statement, never as a read followed by a write: a read-then-write leaves a window in which the other writer commits, and a concurrent edit is exactly the case being defended.

The server cannot merge two versions — they are ciphertext under different item keys — so the only options are refuse or lose one silently.
