<?php

namespace App\Models;

use App\Support\Ciphertext;
use Database\Factories\SecretVersionFactory;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;
use RuntimeException;

/**
 * One superseded payload of a secret.
 *
 * Its ciphertext was sealed by the browser that replaced it, under its own Item
 * Key and bound to this row's UUID at the context `secret.version.payload`. The
 * server has never been able to read it and cannot move it: the binding is what
 * stops an archived version being written back over the live one, which would
 * silently restore a password that was rotated because it leaked.
 *
 * **Content is immutable; the key wrapping is not.** The model refuses an update
 * so that no code path edits a historical payload by accident. A Vault Key
 * rotation still has to re-wrap this row's Item Key, and does so through the
 * query builder along with every other item — see VaultRekeyController, which
 * bypasses model events for every table for the same reason.
 *
 * Deleting *is* allowed, unlike an audit event. History is retained under a
 * policy and can be purged outright, and both of those are features rather than
 * tampering: the log records that it happened.
 *
 * @property int $id
 * @property string $uuid
 * @property int $secret_id
 * @property int $version
 * @property Ciphertext $payload_ct
 * @property Ciphertext $wrapped_item_key
 * @property int $payload_version
 * @property ?int $created_by
 * @property Carbon $created_at
 * @property-read Secret $secret
 * @property-read ?User $author
 */
class SecretVersion extends Model
{
    /** @use HasFactory<SecretVersionFactory> */
    use HasFactory;

    protected $fillable = [
        'uuid',
        'version',
        'payload_ct',
        'wrapped_item_key',
        'payload_version',
        'created_by',
    ];

    public function getRouteKeyName(): string
    {
        return 'uuid';
    }

    protected static function booted(): void
    {
        static::updating(function (): never {
            throw new RuntimeException(
                'A secret version is a record of what a payload used to be, and editing one would '
                .'make the history say something that never happened. Restoring is a new version, '
                .'never a rewrite of an old one.'
            );
        });
    }

    /**
     * Includes soft-deleted secrets, for the same reason every other parent
     * relation here does: a deleted secret keeps its history for the grace
     * period, and a null parent is harder to reason about than a trashed one.
     *
     * @return BelongsTo<Secret, $this>
     */
    public function secret(): BelongsTo
    {
        return $this->belongsTo(Secret::class)->withTrashed();
    }

    /**
     * @return BelongsTo<User, $this>
     */
    public function author(): BelongsTo
    {
        return $this->belongsTo(User::class, 'created_by');
    }

    /**
     * Newest first. History is read backwards from the present, always.
     *
     * Ordered by `version` rather than `created_at`, because the version number
     * is what the concurrency guard actually serialises — two archives written
     * in the same second have an unambiguous order only in that column.
     *
     * @param  Builder<$this>  $query
     * @return Builder<$this>
     */
    public function scopeNewestFirst(Builder $query): Builder
    {
        return $query->orderByDesc('version');
    }

    /**
     * @return array{uuid: string, version: int, payloadCt: string, wrappedItemKey: string, payloadVersion: int, author: ?string, createdAt: string}
     */
    public function toClientArray(): array
    {
        return [
            'uuid' => $this->uuid,
            'version' => $this->version,
            'payloadCt' => $this->payload_ct->base64,
            'wrappedItemKey' => $this->wrapped_item_key->base64,
            'payloadVersion' => $this->payload_version,
            /*
             | A display name, as in the activity feed. Names are already
             | plaintext on `users`; who edited what is accepted leakage, and
             | "who changed this password last March" is most of why a history
             | is worth keeping.
             */
            'author' => $this->author?->display_name,
            'createdAt' => $this->created_at->toIso8601String(),
        ];
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'payload_ct' => Ciphertext::class,
            'wrapped_item_key' => Ciphertext::class,
        ];
    }
}
