<?php

namespace Database\Factories;

use App\Enums\VaultRole;
use App\Models\User;
use App\Models\Vault;
use App\Models\VaultMembership;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Str;

/**
 * @extends Factory<VaultMembership>
 */
class VaultMembershipFactory extends Factory
{
    /**
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'uuid' => (string) Str::uuid7(),
            'vault_id' => Vault::factory(),
            'user_id' => User::factory(),
            'role' => VaultRole::Editor,
            'wrapped_vault_key' => EnvelopeFixtures::sealedEnvelope(),
            'key_epoch' => 1,
        ];
    }

    public function role(VaultRole $role): self
    {
        return $this->state(['role' => $role]);
    }

    public function revoked(): self
    {
        return $this->state(['revoked_at' => now()]);
    }
}
