<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Key Derivation Defaults
    |--------------------------------------------------------------------------
    |
    | Argon2id parameters handed to new clients. Stored per-user in the database
    | once an account exists, so raising these does not require a flag day —
    | existing accounts upgrade silently on their next login.
    |
    | Measured at 731 ms on an Apple M1 (docs/adr/0003-argon2id-implementation.md).
    | `m` is in KiB.
    |
    */

    'kdf' => [
        'm' => (int) env('VAULT_KDF_MEMORY', 64 * 1024),
        't' => (int) env('VAULT_KDF_TIME', 3),
        'p' => (int) env('VAULT_KDF_PARALLELISM', 1),
    ],

    /*
    |--------------------------------------------------------------------------
    | Authentication Throttling
    |--------------------------------------------------------------------------
    |
    | Applied per IP address and, independently, per account. The per-account
    | limit is what stops a distributed attempt on one user; the per-IP limit is
    | what stops one host sweeping many users.
    |
    */

    'throttle' => [
        'login_per_minute' => (int) env('VAULT_LOGIN_THROTTLE', 5),
        'kdf_params_per_minute' => (int) env('VAULT_KDF_PARAMS_THROTTLE', 20),
    ],

    /*
    |--------------------------------------------------------------------------
    | Item Payloads
    |--------------------------------------------------------------------------
    |
    | The schema versions of the encrypted JSON that this build knows how to
    | write. The server cannot read a payload, but it can refuse to store one
    | claiming a version nothing here produces — which is what stops a client
    | writing data that no other client can interpret.
    |
    | Version 2 pads the plaintext to a bucket size before sealing it, so the
    | stored length names a bucket rather than a character count. Version 1 is
    | still accepted because rows written before Phase 4 exist and must stay
    | readable; nothing writes it any more. Dropping it is a data migration,
    | not a config change, and one the server cannot perform.
    |
    | The size cap is deliberately generous compared with a credential and
    | deliberately far below the column limit. It bounds what a compromised
    | session can push into the database, nothing more.
    |
    */

    'payload_versions' => [1, 2],

    'max_payload_bytes' => (int) env('VAULT_MAX_PAYLOAD_BYTES', 65536),

    /*
    |--------------------------------------------------------------------------
    | File Attachments
    |--------------------------------------------------------------------------
    |
    | File bodies are the one thing that does not live in the database. They are
    | encrypted in the browser a chunk at a time and stored as opaque objects
    | keyed by a random UUID, so the disk holds no filename, no extension and
    | nothing that says what any of it is.
    |
    | `chunk_bytes` is the size this build writes; the real value for a given
    | file is in its encrypted manifest, so raising this does not strand
    | anything already uploaded. The cap here is a *ceiling*, not the expected
    | size, because the last chunk of any file is short.
    |
    | `max_bytes` exists because a download is reassembled in the browser.
    | Lifting it is the streaming-download work in docs/05, not a config change.
    |
    | `quota_bytes` is per vault and counts stored ciphertext — the number the
    | server can actually verify by weighing what it has written, rather than a
    | plaintext size the client declares.
    |
    | `orphan_after_hours` is how long a file with chunks still missing is kept
    | before it is swept. Long enough to survive a closed laptop lid and resume
    | the next morning; short enough that an abandoned upload is not permanent.
    |
    */

    'files' => [
        'disk' => env('VAULT_FILES_DISK', 'local'),

        'chunk_bytes' => (int) env('VAULT_FILE_CHUNK_BYTES', 1024 * 1024),

        'max_bytes' => (int) env('VAULT_FILE_MAX_BYTES', 100 * 1024 * 1024),

        'quota_bytes' => (int) env('VAULT_FILE_QUOTA_BYTES', 1024 * 1024 * 1024),

        'orphan_after_hours' => (int) env('VAULT_FILE_ORPHAN_HOURS', 24),

        /*
         | How long a soft-deleted file keeps its bytes on disk. Deleting a file
         | in the interface is reversible for this long; after the sweep it is
         | not, and the interface says so rather than implying otherwise.
         */
        'purge_after_days' => (int) env('VAULT_FILE_PURGE_DAYS', 30),
    ],

];
