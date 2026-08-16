---
paths:
  - bootstrap/app.php
---

# Bootstrap

## Flash nothing — never reintroduce a dontFlash list
App\Http\Middleware\ForgetFlashedInput drops `_old_input` on every response. Do not replace it with a `dontFlash()` list of field names.

One lived here from Phase 0 to 11.5 and drifted: three of its seven entries named fields that never existed, while payload_ct, wrapped_item_key and recovery_auth_key had all arrived without being added. A concurrent-edit conflict is a validation error by design, so the routine two-tabs case was writing two ciphertext payloads and two wrapped Item Keys into the session store.

An allow-list of field names cannot track a schema; it can only look as though it does. Costless to flash nothing: no Blade calls old(), and Vue form state survives a failed submit in the component. tests/Feature/FlashedInputTest.php asserts the session carries nothing, not that it lacks named keys — keep it that way. See docs/07-penetration-test.md F11.
