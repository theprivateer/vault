<?php

namespace App\Models;

use App\Enums\VaultRole;
use App\Support\Ciphertext;
use Database\Factories\VaultMembershipFactory;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;

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
 * @property ?Ciphertext $grant_signature
 * @property ?string $grant_payload
 * @property ?Carbon $accepted_at
 * @property ?Carbon $revoked_at
 * @property-read Vault $vault
 * @property-read User $user
 * @property-read ?User $granter
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
        'grant_signature',
        'grant_payload',
        'accepted_at',
        'revoked_at',
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
     * Who issued this grant, and therefore whose signature it carries.
     *
     * @return BelongsTo<User, $this>
     */
    public function granter(): BelongsTo
    {
        return $this->belongsTo(User::class, 'granted_by');
    }

    /**
     * Everything a browser needs to decide whether to trust this membership.
     *
     * Note what travels: the granter's *public* keys and the signed grant, so
     * the recipient can verify the signature themselves against a fingerprint
     * they pinned. The server's own opinion of whether the grant is valid is not
     * included, because it would be worthless — the server serves the public key
     * too, so it could only ever be checking its own work.
     *
     * @return array{uuid: string, role: string, keyEpoch: int, acceptedAt: ?string, grantSignature: ?string, grantPayload: ?string, grantedBy: ?array{uuid: string, displayName: string, handle: string, ed25519PublicKey: string, x25519PublicKey: string, selfSignature: string, fingerprint: string}, member: array{uuid: string, displayName: string, handle: string}}
     */
    public function toClientArray(): array
    {
        $granter = $this->granter;

        return [
            'uuid' => $this->uuid,
            'role' => (string) $this->role->value,
            'keyEpoch' => $this->key_epoch,
            'acceptedAt' => $this->accepted_at?->toIso8601String(),
            'grantSignature' => $this->grant_signature?->base64,
            'grantPayload' => $this->grant_payload,
            'grantedBy' => $granter?->identity === null ? null : [
                'uuid' => $granter->uuid,
                'displayName' => $granter->display_name,
                'handle' => $granter->handle,
                ...$granter->identity->toPublicBundle(),
            ],
            'member' => [
                'uuid' => $this->user->uuid,
                'displayName' => $this->user->display_name,
                'handle' => $this->user->handle,
            ],
        ];
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
            /*
             | `grant_payload` is deliberately **not** cast to an array.
             |
             | It holds the exact canonical JSON the granter signed, and a
             | signature verifies over bytes. Casting would decode it on read and
             | re-encode it on write, and json_encode is free to differ from the
             | client's serialiser on escaping — `/`, non-ASCII, anything a later
             | field introduces. The result would be grants that no recipient can
             | verify, failing in a way that looks exactly like tampering.
             |
             | Read it as a string; parse a copy if you need the fields.
             */
        ];
    }
}
