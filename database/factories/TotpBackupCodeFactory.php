<?php

namespace Database\Factories;

use App\Models\TotpBackupCode;
use App\Models\User;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Facades\Hash;

/**
 * @extends Factory<TotpBackupCode>
 */
class TotpBackupCodeFactory extends Factory
{
    /**
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'user_id' => User::factory(),
            'code_hash' => Hash::make('abcde-fghij'),
        ];
    }
}
