---
paths:
  - 'routes/**'
---

# Routes

## Authorise vault resources with can: middleware, never $this->authorize()
Route middleware runs before the FormRequest is resolved; a controller `authorize()` call does not.

With the check inside the controller, an unauthorised write to a real record failed validation first and answered 302 with errors, while an unknown UUID answered 404 — telling an attacker which identifiers exist. That is the existence oracle the 404-not-403 rule exists to prevent.

Every vault/lockbox/secret route carries `can:<ability>,<parameter>`. Do not move the check into a controller. Caught by tests/Feature/Vault/AuthorisationTest.php.
