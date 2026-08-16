<?php

namespace App\Models;

use Database\Factories\UserFactory;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\HasOne;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;

/**
 * A user account.
 *
 * Note what is absent: there is no password, and no attribute here can decrypt
 * anything. `auth_key_hash` proves the client knew the password; it is useless
 * for reading data.
 *
 * @property string $uuid
 * @property string $email
 * @property string $display_name
 * @property string $handle
 * @property string $kdf_salt
 * @property array{m: int, t: int, p: int} $kdf_params
 * @property string $auth_key_hash
 */
class User extends Authenticatable
{
    /** @use HasFactory<UserFactory> */
    use HasFactory, HasUuids, Notifiable;

    protected $fillable = [
        'uuid',
        'email',
        'display_name',
        'handle',
        'kdf_salt',
        'kdf_algorithm',
        'kdf_params',
        'auth_key_hash',
    ];

    /**
     * Nothing here is a secret the server can use, but the auth key hash and the
     * TOTP secret have no business appearing in a response.
     *
     * @var list<string>
     */
    protected $hidden = [
        'auth_key_hash',
        'totp_secret_ct',
        'remember_token',
    ];

    /**
     * The framework calls this for `remember me` and the session guard.
     *
     * The auth key hash is the closest analogue we have to a password hash, and
     * the guard needs *something* stable that changes when credentials change,
     * so the session invalidates on a password change.
     */
    public function getAuthPassword(): string
    {
        return $this->auth_key_hash;
    }

    /** @return list<string> */
    public function uniqueIds(): array
    {
        return ['uuid'];
    }

    /**
     * @return HasMany<UserKeyWrap, $this>
     */
    public function keyWraps(): HasMany
    {
        return $this->hasMany(UserKeyWrap::class);
    }

    /**
     * @return HasOne<UserIdentity, $this>
     */
    public function identity(): HasOne
    {
        return $this->hasOne(UserIdentity::class);
    }

    /**
     * Identities this user has retired, newest last.
     *
     * Public halves only, plus the certificate that retired each one. See
     * `UserIdentityArchive` — the private keys are what a rotation exists to
     * discard.
     *
     * @return HasMany<UserIdentityArchive, $this>
     */
    public function identityArchive(): HasMany
    {
        return $this->hasMany(UserIdentityArchive::class);
    }

    /**
     * The most recently retired identity, or null if this user has never
     * rotated. Exactly one link back, deliberately: see docs/03 § Identity key
     * rotation on why a longer chain is not offered.
     */
    public function previousIdentity(): ?UserIdentityArchive
    {
        return $this->identityArchive()->orderByDesc('rotated_at')->orderByDesc('id')->first();
    }

    /**
     * Fingerprints this account has retired, oldest first, lowercase hex.
     *
     * Hex rather than base64 because that is the form a grant records, and a
     * caller that had to convert would be a caller that could convert wrongly.
     *
     * @return list<string>
     */
    public function previousFingerprints(): array
    {
        return array_values($this->identityArchive()
            ->orderBy('rotated_at')
            ->orderBy('id')
            ->get()
            ->map(fn (UserIdentityArchive $archive): string => bin2hex($archive->fingerprint->bytes()))
            ->all());
    }

    /**
     * This account's public keys as another user needs to see them.
     *
     * One method rather than `identity->toPublicBundle()` at three call sites,
     * because the rotation certificate has to travel with the keys everywhere
     * they go. A peer shown a changed fingerprint without it cannot tell a
     * rotation from a substitution — and if only some screens carried it, the
     * ones that did not would show a hard stop for a change the others explained.
     *
     * Null when the account has published nothing, which is a state the sharing
     * flow already handles: such an account cannot be shared with at all.
     *
     * @return array{x25519PublicKey: string, ed25519PublicKey: string, selfSignature: string, fingerprint: string, rotation: ?array{x25519PublicKey: string, ed25519PublicKey: string, selfSignature: string, fingerprint: string, payload: string, signature: string, rotatedAt: string}}|null
     */
    public function publicIdentityBundle(): ?array
    {
        $identity = $this->identity;

        if ($identity === null) {
            return null;
        }

        return [
            ...$identity->toPublicBundle(),
            'rotation' => $this->previousIdentity()?->toClientArray(),
        ];
    }

    /**
     * The encrypted record of whose public keys this user has verified.
     *
     * @return HasOne<UserPinStore, $this>
     */
    public function pinStore(): HasOne
    {
        return $this->hasOne(UserPinStore::class);
    }

    /**
     * @return HasMany<TotpBackupCode, $this>
     */
    public function backupCodes(): HasMany
    {
        return $this->hasMany(TotpBackupCode::class);
    }

    /**
     * @return HasMany<VaultMembership, $this>
     */
    public function vaultMemberships(): HasMany
    {
        return $this->hasMany(VaultMembership::class);
    }

    /**
     * Vaults this user owns.
     *
     * Ownership is an administrative fact — who may delete the vault and who is
     * prompted to re-key it. Access is a membership, and is asked for
     * separately, so an owner who somehow has no membership row can no more
     * read the vault than a stranger.
     *
     * @return HasMany<Vault, $this>
     */
    public function vaults(): HasMany
    {
        return $this->hasMany(Vault::class, 'owner_id');
    }

    /**
     * Everything the browser needs to turn a password into a User Key.
     *
     * Safe to hand to anyone holding a valid session: without the password, the
     * wrapped key is inert. It travels with every authenticated page because the
     * server cannot tell whether the browser is unlocked — that state lives in
     * the Worker, and a full page reload destroys it.
     *
     * Null when no password wrapping exists. Such an account cannot be unlocked
     * by anyone, including the server, so the interface has to say so rather
     * than fail while rendering.
     *
     * @return array{kdfSalt: string, kdfParams: array<string, int>, wrappedUserKey: string, userKeyAad: array{context: string, subject: string, version: int}}|null
     */
    public function unlockBundle(): ?array
    {
        $wrap = $this->keyWraps()->where('method', UserKeyWrap::METHOD_PASSWORD)->first();

        if ($wrap === null) {
            return null;
        }

        return [
            'kdfSalt' => $this->kdf_salt,
            'kdfParams' => $this->kdf_params,
            'wrappedUserKey' => $wrap->wrapped_user_key->base64,
            'userKeyAad' => [
                'context' => 'user.userkey',
                'subject' => $this->uuid,
                'version' => 1,
            ],
        ];
    }

    /**
     * The encrypted list of identities this user has verified, and its version.
     *
     * A user who has verified nobody has no row, which is an empty store rather
     * than an error — but the distinction matters at the other end: the client
     * treats "no store" as "nothing verified yet" and "store that would not
     * open" as "verify everything again". Only one of those is safe to guess at.
     *
     * @return array{pinsCt: ?string, version: int}
     */
    public function pinBundle(): array
    {
        $store = $this->pinStore;

        if ($store === null) {
            return ['pinsCt' => null, 'version' => 0];
        }

        return ['pinsCt' => $store->pins_ct->base64, 'version' => $store->version];
    }

    public function hasTotpEnabled(): bool
    {
        return $this->totp_confirmed_at !== null;
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'kdf_params' => 'array',
            /*
             | The documented exception to "the server can decrypt nothing".
             |
             | A TOTP seed is an authentication factor the server must verify,
             | like a password hash — not user content. It is encrypted with
             | APP_KEY so a database leak alone does not yield working second
             | factors. It protects authentication only: it cannot gate
             | decryption, because decryption never involves the server.
             |
             | No vault data is ever cast this way. See docs/04-data-model.md.
             */
            'totp_secret_ct' => 'encrypted',
            'totp_confirmed_at' => 'datetime',
            'recovery_used_at' => 'datetime',
            'last_login_at' => 'datetime',
        ];
    }
}
