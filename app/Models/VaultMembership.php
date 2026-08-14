<?php

namespace App\Models;

use App\Enums\VaultRole;
use App\Support\Ciphertext;
use Database\Factories\VaultMembershipFactory;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * One user's access to one vault, and their copy of its key.
 *
 * `wrapped_vault_key` is the Vault Key sealed to this member's X25519 public
 * key. The AAD binds it to this membership's UUID, so a server that swapped one
 * member's wrapped key onto another's row would produce an integrity failure in
 * the browser rather than a silent substitution (SR4).
 *
 * @property string $uuid
 * @property VaultRole $role
 * @property Ciphertext $wrapped_vault_key
 * @property int $key_epoch
 * @property-read Vault $vault
 */
class VaultMembership extends Model
{
    /** @use HasFactory<VaultMembershipFactory> */
    use HasFactory;

    protected $fillable = [
        'uuid',
        'user_id',
        'role',
        'wrapped_vault_key',
        'key_epoch',
        'granted_by',
    ];

    public function getRouteKeyName(): string
    {
        return 'uuid';
    }

    /**
     * Includes soft-deleted vaults, so a membership can report that its vault
     * is in the deletion grace period rather than silently vanishing.
     *
     * @return BelongsTo<Vault, $this>
     */
    public function vault(): BelongsTo
    {
        return $this->belongsTo(Vault::class)->withTrashed();
    }

    /**
     * @return BelongsTo<User, $this>
     */
    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    /**
     * Whether this member's key is current.
     *
     * A membership stranded on an old epoch cannot open anything written since
     * the rotation, and the UI must say so rather than showing empty items.
     */
    public function isCurrentEpoch(): bool
    {
        return $this->key_epoch === $this->vault->key_epoch;
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'role' => VaultRole::class,
            'wrapped_vault_key' => Ciphertext::class,
            'grant_signature' => Ciphertext::class,
            'accepted_at' => 'datetime',
            'revoked_at' => 'datetime',
            'grant_payload' => 'array',
        ];
    }
}
