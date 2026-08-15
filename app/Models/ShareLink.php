<?php

namespace App\Models;

use App\Support\Ciphertext;
use Database\Factories\ShareLinkFactory;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;

/**
 * A single secret, sealed for somebody who has no account.
 *
 * **The only ciphertext in this schema that no vault key opens.** `payload_ct`
 * is sealed under a random link key that lives in a URL fragment and nowhere
 * else — not in this table, not in a log, not in the key hierarchy. That is what
 * makes a share a share of one secret rather than a way into the vault it came
 * from, and it is the concrete payoff of per-item keys.
 *
 * The server's whole role is to hold an opaque blob, count how many times it has
 * been handed out, and stop. It cannot read the payload, cannot reconstruct the
 * token from `token_hash`, and cannot tell whether a recipient succeeded in
 * decrypting anything.
 *
 * @property int $id
 * @property string $uuid
 * @property string $token_hash base64 BLAKE2b-256 of the bearer token
 * @property Ciphertext $payload_ct sealed under the link key, not a vault key
 * @property int $payload_version
 * @property int $created_by
 * @property ?int $secret_id
 * @property Carbon $expires_at
 * @property int $max_views
 * @property int $view_count
 * @property ?Carbon $revoked_at
 * @property Carbon $created_at
 */
class ShareLink extends Model
{
    /** @use HasFactory<ShareLinkFactory> */
    use HasFactory;

    /**
     * `created_at` is written explicitly; there is no `updated_at` column,
     * because the only field that moves is the view count and a timestamp
     * beside it would quietly record when a stranger opened the link.
     */
    public $timestamps = false;

    protected $fillable = [
        'uuid',
        'token_hash',
        'payload_ct',
        'payload_version',
        'created_by',
        'secret_id',
        'expires_at',
        'max_views',
        // Written explicitly rather than by the framework, because there is no
        // `updated_at` beside it and `$timestamps = false` means nothing fills
        // it in.
        'created_at',
    ];

    public function getRouteKeyName(): string
    {
        return 'uuid';
    }

    /**
     * @return BelongsTo<User, $this>
     */
    public function creator(): BelongsTo
    {
        return $this->belongsTo(User::class, 'created_by');
    }

    /**
     * Includes soft-deleted secrets: a link outlives the secret it came from by
     * design, so a trashed parent is a state rather than a broken link.
     *
     * @return BelongsTo<Secret, $this>
     */
    public function secret(): BelongsTo
    {
        return $this->belongsTo(Secret::class)->withTrashed();
    }

    /**
     * Whether this link will still hand over its payload.
     *
     * Three ways to be finished, and they are kept separate here even though the
     * response is identical for all of them — the *response* must not
     * distinguish them, but the operator reading a row should be able to.
     */
    public function isRedeemable(): bool
    {
        return $this->revoked_at === null
            && $this->expires_at->isFuture()
            && $this->view_count < $this->max_views;
    }

    /**
     * Everything past its usefulness, for the sweep.
     *
     * Exhausted links are included. A row whose views are spent holds a payload
     * that can never be handed out again, so keeping it is storing a stranger's
     * credential for no purpose — and the audit log already records that the
     * link existed and was used.
     *
     * @param  Builder<$this>  $query
     * @return Builder<$this>
     */
    public function scopeFinished(Builder $query): Builder
    {
        return $query->where(
            fn (Builder $finished): Builder => $finished
                ->where('expires_at', '<', now())
                ->orWhereNotNull('revoked_at')
                ->orWhereColumn('view_count', '>=', 'max_views')
        );
    }

    /**
     * What the creator's own list shows. Never the token, which does not exist
     * here, and never the payload, which would be pointless without the key.
     *
     * @return array{uuid: string, secretUuid: ?string, expiresAt: string, maxViews: int, viewCount: int, revokedAt: ?string, createdAt: string, redeemable: bool}
     */
    public function toClientArray(): array
    {
        return [
            'uuid' => $this->uuid,
            'secretUuid' => $this->secret?->uuid,
            'expiresAt' => $this->expires_at->toIso8601String(),
            'maxViews' => $this->max_views,
            'viewCount' => $this->view_count,
            'revokedAt' => $this->revoked_at?->toIso8601String(),
            'createdAt' => $this->created_at->toIso8601String(),
            'redeemable' => $this->isRedeemable(),
        ];
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'payload_ct' => Ciphertext::class,
            'expires_at' => 'datetime',
            'revoked_at' => 'datetime',
            'created_at' => 'datetime',
        ];
    }
}
