<?php

namespace App\Models;

use App\Support\Ciphertext;
use Database\Factories\UserPinStoreFactory;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * One user's record of whose public keys they have verified.
 *
 * Encrypted under the User Key, so the server can neither read which identities
 * this user has checked nor add one of its own. Both matter: the first would
 * tell a malicious server which substitutions would pass unnoticed, and the
 * second would let it simply pre-approve its own key.
 *
 * What the server *can* still do is drop the row or serve an older copy. That is
 * unavoidable — it holds the bytes — and it is survivable, because a missing pin
 * degrades to a verification prompt rather than a silent accept. The asymmetry
 * is deliberate: forgetting is safe, forging is not, and only forging is
 * prevented here.
 *
 * @property Ciphertext $pins_ct
 * @property int $version
 */
class UserPinStore extends Model
{
    /** @use HasFactory<UserPinStoreFactory> */
    use HasFactory;

    /** A store that has never been written is at version 0, and holds nothing. */
    public const INITIAL_VERSION = 1;

    protected $fillable = [
        'pins_ct',
        'version',
    ];

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
            'pins_ct' => Ciphertext::class,
        ];
    }
}
