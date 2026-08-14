<?php

namespace Database\Factories;

use App\Models\User;
use App\Models\UserKeyWrap;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Facades\Hash;

/**
 * @extends Factory<UserKeyWrap>
 */
class UserKeyWrapFactory extends Factory
{
    /** The auth key a test derives from the recovery kit. */
    public const RECOVERY_AUTH_KEY = 'cmVjb3ZlcnktdGVzdC0zMi1ieXRlLWtleS0wMTIzNDU=';

    /**
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'user_id' => User::factory(),
            'method' => UserKeyWrap::METHOD_PASSWORD,
            // Shaped like a real envelope: 2 header + 24 nonce + 32 key + 16 tag.
            'wrapped_user_key' => base64_encode(random_bytes(74)),
        ];
    }

    public function recovery(): static
    {
        return $this->state(fn (): array => [
            'method' => UserKeyWrap::METHOD_RECOVERY,
            'salt' => base64_encode(random_bytes(16)),
            'verifier_hash' => Hash::make(self::RECOVERY_AUTH_KEY),
        ]);
    }
}
