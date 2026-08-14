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
     * @return HasMany<TotpBackupCode, $this>
     */
    public function backupCodes(): HasMany
    {
        return $this->hasMany(TotpBackupCode::class);
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
