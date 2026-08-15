<?php

namespace App\Models;

use App\Support\Ciphertext;
use Database\Factories\SecretFactory;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\SoftDeletes;

/**
 * A single credential.
 *
 * In 2017 this table had `key` and `value` columns, encrypted with one
 * application-wide key that the server held and used on every request. Here
 * there is one opaque `payload_ct` holding every field — including the type,
 * because a type column would tell the server which rows are TOTP seeds and
 * which are SSH keys, and that is a targeting signal worth nothing to us and
 * quite a lot to an attacker.
 *
 * @property int $id
 * @property string $uuid
 * @property Ciphertext $payload_ct
 * @property Ciphertext $wrapped_item_key
 * @property int $payload_version
 * @property int $current_version
 * @property int $sort_order
 * @property ?int $linked_lockbox_id
 * @property-read Lockbox $lockbox
 * @property-read ?int $versions_count
 */
class Secret extends Model
{
    /** @use HasFactory<SecretFactory> */
    use HasFactory, SoftDeletes;

    /**
     * Where `current_version` starts.
     *
     * Set explicitly on create rather than left to the column default: an
     * Eloquent model does not carry a database default back after an insert,
     * so the freshly created instance would report null and the first update
     * would compare against it.
     */
    public const int INITIAL_VERSION = 1;

    protected $fillable = [
        'uuid',
        'payload_ct',
        'wrapped_item_key',
        'payload_version',
        'current_version',
        'sort_order',
        'linked_lockbox_id',
    ];

    public function getRouteKeyName(): string
    {
        return 'uuid';
    }

    /**
     * Includes soft-deleted lockboxes, for the same reason Lockbox::vault()
     * includes soft-deleted vaults: the authorisation chain must always have a
     * parent to walk, and deletion is a state to check rather than an absence.
     *
     * @return BelongsTo<Lockbox, $this>
     */
    public function lockbox(): BelongsTo
    {
        return $this->belongsTo(Lockbox::class)->withTrashed();
    }

    /**
     * The 2017 lockbox-as-a-value feature: a secret whose value is a pointer to
     * another lockbox. Constrained to the same vault, which is why the edge is
     * visible to the server at all.
     *
     * @return BelongsTo<Lockbox, $this>
     */
    public function linkedLockbox(): BelongsTo
    {
        return $this->belongsTo(Lockbox::class, 'linked_lockbox_id');
    }

    /**
     * Every payload this secret used to have.
     *
     * Each one is separately encrypted under its own Item Key, so the count is
     * all the server knows about them. Cascades on hard delete and survives a
     * soft delete, which is what makes "deleted, restorable for 30 days" mean
     * the same thing for a secret's history as for the secret.
     *
     * @return HasMany<SecretVersion, $this>
     */
    public function versions(): HasMany
    {
        return $this->hasMany(SecretVersion::class);
    }

    /**
     * @return array{uuid: string, lockboxUuid: string, payloadCt: string, wrappedItemKey: string, payloadVersion: int, version: int, sortOrder: int, linkedLockboxUuid: ?string, historyCount: int, updatedAt: ?string}
     */
    public function toClientArray(): array
    {
        return [
            'uuid' => $this->uuid,
            /*
             | Which lockbox this belongs to, so the browser can group a whole
             | vault's secrets without asking again. It leaks nothing the
             | foreign key does not already leak, and searching a vault
             | client-side is impossible without it.
             */
            'lockboxUuid' => $this->lockbox->uuid,
            'payloadCt' => $this->payload_ct->base64,
            'wrappedItemKey' => $this->wrapped_item_key->base64,
            'payloadVersion' => $this->payload_version,
            /*
             | The optimistic-concurrency token. An update is accepted only if
             | the client still believes this number, which is how two people
             | editing one secret produces a refusal rather than a silent loss.
             */
            'version' => $this->current_version,
            'sortOrder' => $this->sort_order,
            'linkedLockboxUuid' => $this->linkedLockbox?->uuid,
            /*
             | How many superseded payloads exist, so a row can offer a history
             | link only where there is one. A count and nothing else: what is
             | in those versions is as opaque to the server here as it is
             | everywhere else, and it defaults to zero rather than issuing a
             | query per row when the caller did not ask for it.
             */
            'historyCount' => is_numeric($this->versions_count ?? null) ? (int) $this->versions_count : 0,
            'updatedAt' => $this->updated_at?->toIso8601String(),
        ];
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'payload_ct' => Ciphertext::class,
            'wrapped_item_key' => Ciphertext::class,
        ];
    }
}
