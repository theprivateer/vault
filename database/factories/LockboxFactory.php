<?php

namespace Database\Factories;

use App\Models\Lockbox;
use App\Models\Vault;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Str;

/**
 * @extends Factory<Lockbox>
 */
class LockboxFactory extends Factory
{
    /**
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'uuid' => (string) Str::uuid7(),
            'vault_id' => Vault::factory(),
            'payload_ct' => EnvelopeFixtures::envelope(140),
            'wrapped_item_key' => EnvelopeFixtures::envelope(48),
            'payload_version' => 1,
            'sort_order' => 0,
        ];
    }
}
