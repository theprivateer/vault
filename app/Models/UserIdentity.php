<?php

namespace App\Models;

use App\Support\Ciphertext;
use Database\Factories\UserIdentityFactory;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;

/**
 * A user's public keys, and their private keys encrypted under the User Key.
 *
 * The server serves the public keys, so the server can lie about them. What
 * stops that is the client: it verifies the self-signature, then compares the
 * fingerprint against its own pinned copy and refuses loudly on a change. This
 * table is not the root of trust.
 *
 * @property Ciphertext $x25519_public_key
 * @property Ciphertext $ed25519_public_key
 * @property Ciphertext $x25519_private_key_ct
 * @property Ciphertext $ed25519_private_key_ct
 * @property Ciphertext $self_signature
 * @property Ciphertext $fingerprint
 * @property ?Carbon $rotated_at
 */
class UserIdentity extends Model
{
    /** @use HasFactory<UserIdentityFactory> */
    use HasFactory;

    protected $fillable = [
        'x25519_public_key',
        'ed25519_public_key',
        'x25519_private_key_ct',
        'ed25519_private_key_ct',
        'self_signature',
        'fingerprint',
    ];

    /**
     * @return BelongsTo<User, $this>
     */
    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    /**
     * The public half only — what another user needs in order to share with
     * this one, and to verify who they are sharing with.
     *
     * @return array{x25519PublicKey: string, ed25519PublicKey: string, selfSignature: string, fingerprint: string}
     */
    public function toPublicBundle(): array
    {
        return [
            'x25519PublicKey' => $this->x25519_public_key->base64,
            'ed25519PublicKey' => $this->ed25519_public_key->base64,
            'selfSignature' => $this->self_signature->base64,
            'fingerprint' => $this->fingerprint->base64,
        ];
    }

    /**
     * The owner's own view: public keys plus their encrypted private halves.
     *
     * Shipping the private key ciphertexts to their owner is safe for the same
     * reason as the wrapped User Key — they are sealed under a key the server
     * has never held, and are inert without the password. The browser needs
     * them because opening any vault means opening a sealed box, and that needs
     * the X25519 private key inside the Worker.
     *
     * @return array{x25519PublicKey: string, ed25519PublicKey: string, x25519PrivateKeyCt: string, ed25519PrivateKeyCt: string, selfSignature: string, fingerprint: string}
     */
    public function toOwnerBundle(): array
    {
        return [
            ...$this->toPublicBundle(),
            'x25519PrivateKeyCt' => $this->x25519_private_key_ct->base64,
            'ed25519PrivateKeyCt' => $this->ed25519_private_key_ct->base64,
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
            'x25519_private_key_ct' => Ciphertext::class,
            'ed25519_private_key_ct' => Ciphertext::class,
            'self_signature' => Ciphertext::class,
            'fingerprint' => Ciphertext::class,
            'rotated_at' => 'datetime',
        ];
    }
}
