<?php

namespace App\Models;

use App\Enums\AuditAction;
use Database\Factories\AuditEventFactory;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;
use RuntimeException;

/**
 * One entry in the tamper-evident log.
 *
 * **Append-only, enforced three times over.** There is no update route; this
 * model throws if anything tries to update or delete it; and in production the
 * application's database role is denied `UPDATE` and `DELETE` on the table. The
 * first two are code, and code can be changed by whoever is changing the code —
 * the third is the one that holds when they are not acting in good faith.
 *
 * The guard is not security theatre against an attacker with a database
 * connection. It is there for the ordinary case: a future `$event->update(...)`
 * written without realising, or a `truncate` in a seeder, silently invalidating
 * every hash after the row it touched.
 *
 * @property int $id
 * @property int $seq
 * @property string $prev_hash base64
 * @property string $hash base64
 * @property ?string $actor_uuid
 * @property AuditAction $action
 * @property ?string $subject_type
 * @property ?string $subject_uuid
 * @property string $metadata canonical JSON, hashed verbatim
 * @property ?string $actor_signature base64 Ed25519
 * @property ?string $signed_payload the exact bytes the client signed
 * @property ?string $ip_hash
 * @property ?string $user_agent_hash
 * @property Carbon $created_at
 */
class AuditEvent extends Model
{
    /** @use HasFactory<AuditEventFactory> */
    use HasFactory;

    /**
     * `created_at` is written explicitly by the recorder, because it is part of
     * what the chain hashes and must be settled before the hash is computed
     * rather than filled in by the framework afterwards.
     */
    public $timestamps = false;

    protected $guarded = [];

    protected static function booted(): void
    {
        static::updating(function (): never {
            throw new RuntimeException(
                'Audit events are append-only. Updating one would invalidate every hash after it, '
                .'which is precisely the tampering the chain exists to make visible.'
            );
        });

        static::deleting(function (): never {
            throw new RuntimeException(
                'Audit events are append-only. Deleting one leaves a gap in `seq`, which '
                .'`vault:audit-verify` reports — but the record is gone either way.'
            );
        });
    }

    /**
     * The acting user, resolved by UUID rather than a foreign key.
     *
     * Deliberately not a constrained relation: a cascade or a `nullOnDelete`
     * would rewrite historical rows when an account is closed, and rewriting a
     * row is exactly what the chain reports as tampering. If the account is
     * gone, this returns null and the UUID in the row still says who it was.
     *
     * @return BelongsTo<User, $this>
     */
    public function actor(): BelongsTo
    {
        return $this->belongsTo(User::class, 'actor_uuid', 'uuid');
    }

    /**
     * @return array<string, mixed>
     */
    public function decodedMetadata(): array
    {
        $decoded = json_decode($this->metadata, true);

        if (! is_array($decoded)) {
            return [];
        }

        $metadata = [];

        foreach ($decoded as $key => $value) {
            $metadata[(string) $key] = $value;
        }

        return $metadata;
    }

    /**
     * Events about one vault, including the things that happened inside it.
     *
     * Scoped by the subject UUIDs of the vault's own children rather than by a
     * `vault_id` column, because there isn't one — the subject is polymorphic so
     * that a record outlives the thing it describes.
     *
     * @param  Builder<AuditEvent>  $query
     * @param  list<string>  $subjectUuids
     * @return Builder<AuditEvent>
     */
    public function scopeAboutAny(Builder $query, array $subjectUuids): Builder
    {
        return $query->whereIn('subject_uuid', $subjectUuids);
    }

    /**
     * @return array{seq: int, action: string, description: string, actor: ?string, subjectType: ?string, subjectUuid: ?string, metadata: array<string, mixed>, signed: bool, at: string}
     */
    public function toClientArray(): array
    {
        return [
            'seq' => $this->seq,
            'action' => $this->action->value,
            'description' => $this->action->describe(),
            /*
             | The display name, not the UUID: this view is read by a person
             | deciding whether they recognise what happened. Names are already
             | plaintext on `users` and named as accepted leakage in
             | docs/02-threat-model.md.
             */
            'actor' => $this->actor?->display_name,
            'subjectType' => $this->subject_type,
            'subjectUuid' => $this->subject_uuid,
            'metadata' => $this->decodedMetadata(),
            /*
             | Whether the browser signed for this, rather than the server merely
             | asserting it. The interface says which, because the two carry
             | genuinely different weight.
             */
            'signed' => $this->actor_signature !== null,
            'at' => $this->created_at->toIso8601String(),
        ];
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'action' => AuditAction::class,
            'created_at' => 'datetime',
        ];
    }
}
