<?php

namespace Database\Factories;

use App\Enums\AuditAction;
use App\Models\AuditEvent;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<AuditEvent>
 */
class AuditEventFactory extends Factory
{
    protected $model = AuditEvent::class;

    /**
     * A structurally valid event whose **hash is deliberately wrong**.
     *
     * There is no honest way for a factory to produce a chained entry: the hash
     * depends on the entry before it, so a row invented in isolation is by
     * definition not part of a chain. Tests that need a real chain go through
     * `AuditLog::record`, which is the only writer; this factory exists for the
     * cases that need a row's *shape* and nothing else.
     *
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'seq' => 1,
            'prev_hash' => base64_encode(str_repeat("\0", 32)),
            'hash' => base64_encode(random_bytes(32)),
            'actor_uuid' => null,
            'action' => AuditAction::LoggedIn,
            'subject_type' => null,
            'subject_uuid' => null,
            'metadata' => '{}',
            'created_at' => now()->startOfSecond(),
        ];
    }
}
