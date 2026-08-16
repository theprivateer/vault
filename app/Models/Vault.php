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
use Illuminate\Support\Facades\Config;

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
 * @property ?Carbon $key_rotated_at
 * @property ?int $rotate_after_days
 * @property ?int $history_max_versions
 * @property ?int $history_max_age_days
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
        'key_rotated_at',
        'rotate_after_days',
        'history_max_versions',
        'history_max_age_days',
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
     * How many people other than this one still hold a key to the vault.
     *
     * Counted from live memberships rather than from `owner_id`, because a
     * membership row *is* a sealed copy of the Vault Key. Deleting a vault that
     * has any leaves those copies wrapping rows nobody can reach — the members
     * keep a key and lose everything it opens — which is why deletion is refused
     * until the vault has been handed over or everyone else has been revoked.
     *
     * Revoked rows do not count. Their access was already cut, and their sealed
     * key opens nothing written since the re-key that revocation demanded.
     */
    public function otherLiveMembers(User $user): int
    {
        return $this->memberships()
            ->whereNull('revoked_at')
            ->where('user_id', '!=', $user->getKey())
            ->count();
    }

    /**
     * How many superseded payloads a secret in this vault keeps.
     *
     * Null on the column means "whatever the deployment's default is", so
     * raising the default lifts every vault that never expressed an opinion.
     * Zero is a real answer and not an absent one — it is how a vault whose
     * contents get rotated *because* they leak turns history off.
     */
    public function historyMaxVersions(): int
    {
        return $this->history_max_versions ?? Config::integer('vault.history.max_versions');
    }

    public function historyMaxAgeDays(): int
    {
        return $this->history_max_age_days ?? Config::integer('vault.history.max_age_days');
    }

    /**
     * How often this vault would like to be reminded to rotate, in days.
     *
     * Zero means never, and is a real answer rather than an absent one — the
     * same distinction the history columns draw. Null defers to the deployment.
     */
    public function rotateAfterDays(): int
    {
        return $this->rotate_after_days ?? Config::integer('vault.rotation.after_days');
    }

    /**
     * When this key becomes old enough to mention, or null if never.
     *
     * A reminder and nothing more. Nothing on the server can rotate a Vault Key,
     * because unwrapping the current one needs a member's browser — so an
     * overdue vault stays overdue until somebody opens it, and no job will
     * quietly resolve it.
     */
    public function rotationDueAt(): ?Carbon
    {
        $days = $this->rotateAfterDays();

        if ($days < 1 || $this->key_rotated_at === null) {
            return null;
        }

        return $this->key_rotated_at->copy()->addDays($days);
    }

    public function isRotationDue(): bool
    {
        return $this->rotationDueAt()?->isPast() === true;
    }

    /**
     * What the browser needs in order to open this vault.
     *
     * Note what is *not* here: any associated data. The client builds its own
     * AAD from these UUIDs. If the server supplied it, a malicious server could
     * hand over a ciphertext along with instructions to verify it against the
     * wrong record — which is precisely the binding AAD exists to provide.
     *
     * @return array{uuid: string, payloadCt: string, wrappedItemKey: string, payloadVersion: int, keyEpoch: int, updatedAt: ?string, rotation: array{rotatedAt: ?string, afterDays: int, dueAt: ?string, isDue: bool, isDefault: bool}, history: array{maxVersions: int, maxAgeDays: int, isDefault: bool}, membership: array{uuid: string, role: string, wrappedVaultKey: string, keyEpoch: int}}
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
            /*
             | How old this key is, and whether anyone asked to be told. The
             | effective policy rather than the raw column, for the same reason
             | as `history` below: a page showing "null" would be describing a
             | setting instead of the behaviour.
             */
            'rotation' => [
                'rotatedAt' => $this->key_rotated_at?->toIso8601String(),
                'afterDays' => $this->rotateAfterDays(),
                'dueAt' => $this->rotationDueAt()?->toIso8601String(),
                'isDue' => $this->isRotationDue(),
                'isDefault' => $this->rotate_after_days === null,
            ],
            /*
             | The effective policy, not the raw columns: a page showing "null"
             | where a number is enforced would be describing a setting rather
             | than the behaviour. `isDefault` is what lets the interface say
             | whether this vault has an opinion of its own.
             */
            'history' => [
                'maxVersions' => $this->historyMaxVersions(),
                'maxAgeDays' => $this->historyMaxAgeDays(),
                'isDefault' => $this->history_max_versions === null
                    && $this->history_max_age_days === null,
            ],
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
            'key_rotated_at' => 'datetime',
        ];
    }
}
