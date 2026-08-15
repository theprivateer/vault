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

];
