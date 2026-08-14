<?php

namespace Database\Factories;

use App\Enums\VaultRole;
use App\Models\User;
use App\Models\Vault;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Str;

/**
 * @extends Factory<Vault>
 */
class VaultFactory extends Factory
{
    /**
     * Real envelope headers over random bodies — see EnvelopeFixtures.
     *
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'uuid' => (string) Str::uuid7(),
            'owner_id' => User::factory(),
            'payload_ct' => EnvelopeFixtures::envelope(120),
            'wrapped_item_key' => EnvelopeFixtures::envelope(48),
            'payload_version' => 1,
            'key_epoch' => 1,
        ];
    }

    /** Gives a user a live membership at the vault's current epoch. */
    public function withMember(User $user, VaultRole $role = VaultRole::Owner): self
    {
        return $this->afterCreating(function (Vault $vault) use ($user, $role): void {
            $vault->memberships()->create([
                'uuid' => (string) Str::uuid7(),
                'user_id' => $user->getKey(),
                'role' => $role,
                'wrapped_vault_key' => EnvelopeFixtures::sealedEnvelope(),
                'key_epoch' => $vault->key_epoch,
                'granted_by' => $vault->owner_id,
            ]);
        });
    }

    /** A vault owned by a user, with the owner membership that implies. */
    public function ownedBy(User $user): self
    {
        return $this->for($user, 'owner')->withMember($user, VaultRole::Owner);
    }
}
