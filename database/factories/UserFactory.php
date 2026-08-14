<?php

namespace Database\Factories;

use App\Models\User;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;

/**
 * @extends Factory<User>
 */
class UserFactory extends Factory
{
    /**
     * A fixed auth key so tests can sign in without deriving one.
     *
     * Real accounts never use this: the auth key is Argon2id output from a
     * password that only ever exists in a browser.
     */
    public const AUTH_KEY = 'MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=';

    /**
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'uuid' => (string) Str::uuid7(),
            'email' => fake()->unique()->safeEmail(),
            'display_name' => fake()->name(),
            'handle' => Str::lower(fake()->unique()->userName()),
            'kdf_salt' => base64_encode(random_bytes(16)),
            'kdf_algorithm' => 'argon2id',
            'kdf_params' => ['m' => 8, 't' => 1, 'p' => 1],
            'auth_key_hash' => Hash::make(self::AUTH_KEY),
            // Model::shouldBeStrict() makes reading an unloaded attribute throw,
            // and the session guard reads this on logout.
            'remember_token' => Str::random(10),
        ];
    }

    public function withTotp(string $secret = 'JBSWY3DPEHPK3PXP'): static
    {
        return $this->state(fn (): array => [
            'totp_secret_ct' => $secret,
            'totp_confirmed_at' => now(),
        ]);
    }
}
