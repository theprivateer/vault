<?php

namespace Database\Factories;

use App\Models\Lockbox;
use App\Models\Secret;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Str;

/**
 * @extends Factory<Secret>
 */
class SecretFactory extends Factory
{
    /**
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'uuid' => (string) Str::uuid7(),
            'lockbox_id' => Lockbox::factory(),
            'payload_ct' => EnvelopeFixtures::envelope(200),
            'wrapped_item_key' => EnvelopeFixtures::envelope(48),
            'payload_version' => 1,
            'sort_order' => 0,
            'current_version' => 1,
        ];
    }
}
