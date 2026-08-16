---
paths:
  - 'routes/**'
---

# Routes

## Authorise vault resources with can: middleware, never $this->authorize()
Route middleware runs before the FormRequest is resolved; a controller `authorize()` call does not.

With the check inside the controller, an unauthorised write to a real record failed validation first and answered 302 with errors, while an unknown UUID answered 404 — telling an attacker which identifiers exist. That is the existence oracle the 404-not-403 rule exists to prevent.

Every vault/lockbox/secret route carries `can:<ability>,<parameter>`. Do not move the check into a controller. Caught by tests/Feature/Vault/AuthorisationTest.php.

## Every route carries a rate limiter
The `auth` group carries `throttle:authenticated` (per account and per address) and the `guest` group carries `throttle:guest`. Routes outside both name their own.

tests/Feature/RateLimitTest.php sweeps the whole route table and fails on anything unlimited, with a short allow-list for `/up` and the `/` redirect. That sweep is also what found `storage.local` and `storage.local.upload` — two endpoints a framework default had registered on the disk holding every file ciphertext. Keep the allow-list short and add reasons, not entries.
