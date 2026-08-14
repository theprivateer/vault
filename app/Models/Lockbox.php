<?php

namespace App\Models;

use App\Support\Ciphertext;
use Database\Factories\LockboxFactory;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\SoftDeletes;

/**
 * A group of secrets inside a vault.
 *
 * The 2017 `control` boolean is gone — that concept was removed by its own
 * migration back then anyway.
 *
 * @property string $uuid
 * @property Ciphertext $payload_ct
 * @property Ciphertext $wrapped_item_key
 * @property int $payload_version
 * @property int $sort_order
 * @property-read Vault $vault
 */
class Lockbox extends Model
{
    /** @use HasFactory<LockboxFactory> */
    use HasFactory, SoftDeletes;

    protected $fillable = [
        'uuid',
        'payload_ct',
        'wrapped_item_key',
        'payload_version',
        'sort_order',
    ];

    public function getRouteKeyName(): string
    {
        return 'uuid';
    }

    /**
     * Deliberately includes soft-deleted vaults.
     *
     * A lockbox in a deleted vault is still a routable row until the purge job
     * runs, so if this relation hid the parent it would return null and the
     * authorisation check would have nothing to check against. Better that the
     * vault is always present and its deleted state is an explicit question —
     * which the policy asks. See LockboxPolicy.
     *
     * @return BelongsTo<Vault, $this>
     */
    public function vault(): BelongsTo
    {
        return $this->belongsTo(Vault::class)->withTrashed();
    }

    /**
     * @return HasMany<Secret, $this>
     */
    public function secrets(): HasMany
    {
        return $this->hasMany(Secret::class);
    }

    /**
     * @return array{uuid: string, payloadCt: string, wrappedItemKey: string, payloadVersion: int, sortOrder: int, secretCount: int, updatedAt: ?string}
     */
    public function toClientArray(): array
    {
        return [
            'uuid' => $this->uuid,
            'payloadCt' => $this->payload_ct->base64,
            'wrappedItemKey' => $this->wrapped_item_key->base64,
            'payloadVersion' => $this->payload_version,
            'sortOrder' => $this->sort_order,
            // Leaks how many secrets a lockbox holds, which the row count
            // leaks anyway. Recorded in docs/02-threat-model.md.
            'secretCount' => (int) ($this->secrets_count ?? $this->secrets()->count()),
            'updatedAt' => $this->updated_at?->toIso8601String(),
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
