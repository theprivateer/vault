<?php

namespace Database\Factories;

use App\Models\Secret;
use App\Models\ShareLink;
use App\Models\User;
use App\Support\ShareToken;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Str;

/**
 * @extends Factory<ShareLink>
 */
class ShareLinkFactory extends Factory
{
    /**
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'uuid' => (string) Str::uuid7(),
            // A real token, hashed the way the controller hashes one, so a test
            // can redeem this row through the actual endpoint.
            'token_hash' => ShareToken::hash(self::token()),
            'payload_ct' => EnvelopeFixtures::envelope(200),
            'payload_version' => 2,
            'created_by' => User::factory(),
            'secret_id' => Secret::factory(),
            'expires_at' => now()->addDay(),
            'max_views' => 1,
            'view_count' => 0,
            'created_at' => now(),
        ];
    }

    /** A fresh base64url token, in the form the recipient's browser posts. */
    public static function token(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(ShareToken::BYTES)), '+/', '-_'), '=');
    }

    /** Built around a token the caller already holds, so it can be redeemed. */
    public function withToken(string $token): self
    {
        return $this->state(fn (): array => ['token_hash' => ShareToken::hash($token)]);
    }

    public function expired(): self
    {
        return $this->state(fn (): array => ['expires_at' => now()->subHour()]);
    }

    public function exhausted(): self
    {
        return $this->state(fn (): array => ['view_count' => 1, 'max_views' => 1]);
    }

    public function revoked(): self
    {
        return $this->state(fn (): array => ['revoked_at' => now()]);
    }
}
