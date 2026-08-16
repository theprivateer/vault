<?php

namespace App\Models;

use App\Support\Ciphertext;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;

/**
 * A retired identity, and the certificate its holder signed to retire it.
 *
 * Public key material only — see the migration for why the private halves are
 * not here and never will be.
 *
 * @property Ciphertext $x25519_public_key
 * @property Ciphertext $ed25519_public_key
 * @property Ciphertext $self_signature
 * @property Ciphertext $fingerprint
 * @property string $rotation_payload
 * @property Ciphertext $rotation_signature
 * @property Carbon $rotated_at
 */
class UserIdentityArchive extends Model
{
    protected $table = 'user_identity_archive';

    protected $fillable = [
        'x25519_public_key',
        'ed25519_public_key',
        'self_signature',
        'fingerprint',
        'rotation_payload',
        'rotation_signature',
        'rotated_at',
    ];

    /**
     * @return BelongsTo<User, $this>
     */
    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    /**
     * What a peer needs to decide whether this was a rotation or a substitution.
     *
     * The retired public keys travel with the certificate because the peer has
     * to establish that these are the keys *they* pinned before the signature
     * means anything — they hold a fingerprint, not a key, and a fingerprint
     * cannot verify a signature. Recomputing it from these two and comparing
     * against the pin is what makes the rest of it evidence.
     *
     * @return array{x25519PublicKey: string, ed25519PublicKey: string, selfSignature: string, fingerprint: string, payload: string, signature: string, rotatedAt: string}
     */
    public function toClientArray(): array
    {
        return [
            'x25519PublicKey' => $this->x25519_public_key->base64,
            'ed25519PublicKey' => $this->ed25519_public_key->base64,
            'selfSignature' => $this->self_signature->base64,
            'fingerprint' => $this->fingerprint->base64,
            'payload' => $this->rotation_payload,
            'signature' => $this->rotation_signature->base64,
            'rotatedAt' => $this->rotated_at->toIso8601String(),
        ];
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'x25519_public_key' => Ciphertext::class,
            'ed25519_public_key' => Ciphertext::class,
            'self_signature' => Ciphertext::class,
            'fingerprint' => Ciphertext::class,
            'rotation_signature' => Ciphertext::class,
            'rotated_at' => 'datetime',
            /*
             | `rotation_payload` is deliberately not cast, exactly as
             | `VaultMembership::grant_payload` is not. It holds the precise
             | bytes the retired key signed, and a decode/re-encode round trip is
             | free to change the escaping — producing certificates no peer can
             | verify, failing in a way indistinguishable from an attack.
             */
        ];
    }
}
