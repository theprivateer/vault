<?php

namespace App\Models;

use App\Support\Ciphertext;
use Database\Factories\UserKeyWrapFactory;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * A wrapping of the User Key that some unlock method can undo.
 *
 * The User Key itself is never here — only a copy of it sealed under a key
 * derived from the user's password, or from their recovery code. The server
 * holds neither.
 *
 * @property Ciphertext $wrapped_user_key
 */
class UserKeyWrap extends Model
{
    /** @use HasFactory<UserKeyWrapFactory> */
    use HasFactory;

    public const METHOD_PASSWORD = 'password';

    public const METHOD_RECOVERY = 'recovery';

    protected $fillable = [
        'method',
        'wrapped_user_key',
        'salt',
        'label',
        'verifier_hash',
    ];

    /** @var list<string> */
    protected $hidden = ['verifier_hash'];

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
            'wrapped_user_key' => Ciphertext::class,
            'last_used_at' => 'datetime',
        ];
    }
}
