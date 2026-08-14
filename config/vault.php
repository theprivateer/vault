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

];
