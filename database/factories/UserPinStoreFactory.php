<?php

namespace Database\Factories;

use App\Models\User;
use App\Models\UserPinStore;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<UserPinStore>
 */
class UserPinStoreFactory extends Factory
{
    /**
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'user_id' => User::factory(),
            'pins_ct' => EnvelopeFixtures::envelope(64),
            'version' => UserPinStore::INITIAL_VERSION,
        ];
    }
}
