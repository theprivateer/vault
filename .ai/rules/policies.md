---
paths:
  - 'app/Policies/**'
---

# Policies

## Deny as 404, and check the whole parent chain for soft deletes
Every denial is `Response::denyAsNotFound()`. A 403 confirms the record exists, which is an existence oracle over UUIDs the caller should know nothing about.

Access is a live `vault_memberships` row — never ownership inferred from a foreign key, never a vault_id from the request.

Soft-deleting a vault leaves its lockboxes and secrets as routable rows for the grace period, so a policy must check the whole chain above a record for `trashed()`, not just the record. Parent relations are declared `withTrashed()` so a deleted parent is a state to test rather than a null to trip over.
