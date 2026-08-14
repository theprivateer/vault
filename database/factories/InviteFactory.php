<?php

namespace Database\Factories;

use App\Models\Invite;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Str;

/**
 * @extends Factory<Invite>
 */
class InviteFactory extends Factory
{
    /**
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'uuid' => (string) Str::uuid7(),
            'email' => fake()->unique()->safeEmail(),
            'token_hash' => Invite::hashToken(Invite::generateToken()),
            'expires_at' => now()->addDays(7),
        ];
    }

    /** Returns the plaintext token alongside, since only its hash is stored. */
    public function withToken(string $token): static
    {
        return $this->state(fn (): array => ['token_hash' => Invite::hashToken($token)]);
    }

    public function expired(): static
    {
        return $this->state(fn (): array => ['expires_at' => now()->subDay()]);
    }

    public function accepted(): static
    {
        return $this->state(fn (): array => ['accepted_at' => now()]);
    }
}
