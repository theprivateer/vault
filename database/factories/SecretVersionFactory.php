<?php

namespace Database\Factories;

use App\Models\Secret;
use App\Models\SecretVersion;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Str;

/**
 * @extends Factory<SecretVersion>
 */
class SecretVersionFactory extends Factory
{
    /**
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'uuid' => (string) Str::uuid7(),
            'secret_id' => Secret::factory(),
            'version' => 1,
            'payload_ct' => EnvelopeFixtures::envelope(200),
            'wrapped_item_key' => EnvelopeFixtures::envelope(48),
            'payload_version' => 2,
        ];
    }

    /** Aged, for the retention sweep — which is the only thing that reads it. */
    public function archivedDaysAgo(int $days): self
    {
        return $this->state(fn (): array => ['created_at' => now()->subDays($days)]);
    }
}
