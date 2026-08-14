<?php

namespace Database\Factories;

use App\Models\User;
use App\Models\UserIdentity;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<UserIdentity>
 */
class UserIdentityFactory extends Factory
{
    /**
     * Correctly sized but cryptographically meaningless. The server only ever
     * stores and serves these, so tests that exercise the server do not need
     * them to verify — the tests that check verification live in the crypto
     * suite, where real keys are generated.
     *
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'user_id' => User::factory(),
            'x25519_public_key' => base64_encode(random_bytes(32)),
            'ed25519_public_key' => base64_encode(random_bytes(32)),
            'x25519_private_key_ct' => base64_encode(random_bytes(74)),
            'ed25519_private_key_ct' => base64_encode(random_bytes(74)),
            'self_signature' => base64_encode(random_bytes(64)),
            'fingerprint' => base64_encode(random_bytes(32)),
        ];
    }
}
