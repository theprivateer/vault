<?php

namespace App\Models;

use App\Enums\VaultRole;
use App\Support\Ciphertext;
use Database\Factories\VaultFactory;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Support\Carbon;

/**
 * A vault: the unit of sharing, and the root of one key hierarchy.
 *
 * Nothing on this model can read a vault's contents. `payload_ct` holds the
 * name and description, encrypted under an Item Key which is wrapped by a Vault
 * Key the server has never seen — it exists only sealed to each member's public
 * key on their membership row.
 *
 * @property string $uuid
 * @property Ciphertext $payload_ct
 * @property Ciphertext $wrapped_item_key
 * @property int $payload_version
 * @property int $key_epoch
 * @property ?Carbon $rekey_required_at
 */
class Vault extends Model
{
    /** @use HasFactory<VaultFactory> */
    use HasFactory, SoftDeletes;

    /** Every vault starts here; rotation advances it (Phase 5). */
    public const INITIAL_KEY_EPOCH = 1;

    protected $fillable = [
        'uuid',
        'payload_ct',
        'wrapped_item_key',
        'payload_version',
        'key_epoch',
    ];

    /** UUIDs in URLs; the auto-increment key stays internal. */
    public function getRouteKeyName(): string
    {
        return 'uuid';
    }

    /**
     * @return BelongsTo<User, $this>
     */
    public function owner(): BelongsTo
    {
        return $this->belongsTo(User::class, 'owner_id');
    }

    /**
     * @return HasMany<VaultMembership, $this>
     */
    public function memberships(): HasMany
    {
        return $this->hasMany(VaultMembership::class);
    }

    /**
     * @return HasMany<Lockbox, $this>
     */
    public function lockboxes(): HasMany
    {
        return $this->hasMany(Lockbox::class);
    }

    /**
     * The live membership for a user, or null.
     *
     * A revoked membership is not a membership: revocation cuts API access
     * immediately, before any re-key has happened, because that part is instant
     * and enforceable while re-keying is not.
     */
    public function membershipFor(User $user): ?VaultMembership
    {
        return $this->memberships()
            ->where('user_id', $user->getKey())
            ->whereNull('revoked_at')
            ->first();
    }

    public function roleFor(User $user): ?VaultRole
    {
        return $this->membershipFor($user)?->role;
    }

    /**
     * What the browser needs in order to open this vault.
     *
     * Note what is *not* here: any associated data. The client builds its own
     * AAD from these UUIDs. If the server supplied it, a malicious server could
     * hand over a ciphertext along with instructions to verify it against the
     * wrong record — which is precisely the binding AAD exists to provide.
     *
     * @return array{uuid: string, payloadCt: string, wrappedItemKey: string, payloadVersion: int, keyEpoch: int, updatedAt: ?string, membership: array{uuid: string, role: string, wrappedVaultKey: string, keyEpoch: int}}
     */
    public function toClientArray(VaultMembership $membership): array
    {
        return [
            'uuid' => $this->uuid,
            'payloadCt' => $this->payload_ct->base64,
            'wrappedItemKey' => $this->wrapped_item_key->base64,
            'payloadVersion' => $this->payload_version,
            'keyEpoch' => $this->key_epoch,
            'updatedAt' => $this->updated_at?->toIso8601String(),
            'membership' => [
                'uuid' => $membership->uuid,
                'role' => $membership->role->value,
                'wrappedVaultKey' => $membership->wrapped_vault_key->base64,
                'keyEpoch' => $membership->key_epoch,
            ],
        ];
    }

    /**
     * @param  Builder<$this>  $query
     * @return Builder<$this>
     */
    public function scopeVisibleTo(Builder $query, User $user): Builder
    {
        return $query->whereHas(
            'memberships',
            fn (Builder $memberships): Builder => $memberships
                ->where('user_id', $user->getKey())
                ->whereNull('revoked_at')
        );
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'payload_ct' => Ciphertext::class,
            'wrapped_item_key' => Ciphertext::class,
            'rekey_required_at' => 'datetime',
        ];
    }
}
