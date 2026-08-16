---
paths:
  - app/Http/Controllers/Auth/KdfUpgradeController.php
  - 'app/Http/Controllers/Auth/**'
---

# Auth

## The KDF upgrade endpoint must demand the current auth key
Without `current_auth_key`, this is account takeover from a session alone: injected script asks the Worker to re-wrap the User Key under a password it chose and posts the result. The wrapping is opaque to the server, so nothing else distinguishes that from a genuine upgrade. Same guard, same reason, as the password-change endpoint.

`KdfPolicy::accepts` refuses parameters weaker than the account already uses or than `config('vault.kdf')` requires — an upgrade endpoint that accepts a downgrade is a downgrade endpoint. Compared per parameter, never as a combined cost: memory hardness is what makes Argon2id expensive on rented hardware and must not be tradeable for more passes.

It runs at login only, because re-wrapping needs the password and the password exists in the browser for exactly one form submission. A failure there is swallowed on purpose — the login succeeded, the account just stays on its old parameters. Guarded by tests/Feature/Vault/KdfUpgradeTest.php.

## Pre-auth endpoints must perform the same number of password hashes on every path
An address that does not exist must cost what a wrong credential costs. Both halves were wrong before Phase 11: login generated its decoy on the spot (two bcrypt rounds against one, so unknown answered twice as slowly), and /recover short-circuited the `&&` and hashed nothing at all.

Rule: resolve `App\Support\DecoyHash::forVerification()` before the branch, run exactly one `Hash::check` against the stored hash or the decoy, then decide. Never put a `Hash::make` on one branch only.

tests/Feature/Auth/TimingTest.php asserts hash-operation counts, not a clock. See docs/07-penetration-test.md F1–F3.
