---
paths:
  - app/Http/Controllers/Auth/KdfUpgradeController.php
---

# Auth

## The KDF upgrade endpoint must demand the current auth key
Without `current_auth_key`, this is account takeover from a session alone: injected script asks the Worker to re-wrap the User Key under a password it chose and posts the result. The wrapping is opaque to the server, so nothing else distinguishes that from a genuine upgrade. Same guard, same reason, as the password-change endpoint.

`KdfPolicy::accepts` refuses parameters weaker than the account already uses or than `config('vault.kdf')` requires — an upgrade endpoint that accepts a downgrade is a downgrade endpoint. Compared per parameter, never as a combined cost: memory hardness is what makes Argon2id expensive on rented hardware and must not be tradeable for more passes.

It runs at login only, because re-wrapping needs the password and the password exists in the browser for exactly one form submission. A failure there is swallowed on purpose — the login succeeded, the account just stays on its old parameters. Guarded by tests/Feature/Vault/KdfUpgradeTest.php.
