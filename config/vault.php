<?php

return [

    'key'           => env('VAULT_KEY'),

    'cipher'        => 'AES-256-CBC',

    'registrations' => env('VAULT_REGISTRATIONS', true),

    'splash_page'   => env('VAULT_SPLASH_PAGE', true),

    'credit'        => env('DISPLAY_VAULT_CREDIT', true),

];