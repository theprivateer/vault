<?php

namespace App\Models;

use Database\Factories\TotpBackupCodeFactory;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * A single-use backup code for the TOTP second factor.
 *
 * Hashed, because the server has no reason to read one back. Distinct from the
 * recovery *kit*, which unlocks the vault itself and never touches the server.
 */
class TotpBackupCode extends Model
{
    /** @use HasFactory<TotpBackupCodeFactory> */
    use HasFactory;

    protected $fillable = ['code_hash'];

    /**
     * @return BelongsTo<User, $this>
     */
    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'used_at' => 'datetime',
        ];
    }
}
