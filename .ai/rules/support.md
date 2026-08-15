---
paths:
  - app/Support/AuditLog.php
---

# Support

## AuditLog is the only writer, and metadata keys are a closed set
Never insert into `audit_events` directly. `seq`, `prev_hash` and the `audit_chain` head move together inside one transaction with the head row locked; a write that bypasses that forks the chain.

Record inside the caller's transaction wherever there is one, so the action and the record of it commit together. An audit entry written after a committed change can be lost by a crash in between.

`AuditMetadata::KEYS` is a closed allow-list, like AAD_CONTEXTS. This column is the shortest path in the project from decrypted content to a permanent, append-only record of it — "just log the name so the feed reads nicely" is the change to refuse. Admission test: could the value differ between two users doing the same thing to different data? A role, epoch, count or index cannot. A name, note, filename or URL can.

The canonical form is NUL-joined fields, not JSON — JSON has encoder flags that can change the bytes of a hash computed years earlier. `metadata` is hashed exactly as stored, which is why its column is `text` and not `json`.

`actor_uuid` and `subject_uuid` are UUIDs, never foreign keys. A cascade or nullOnDelete would rewrite historical rows, and a rewritten row is what the chain reports as tampering.
