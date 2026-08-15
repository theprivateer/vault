<?php

namespace App\Models;

use App\Support\ChunkBitmap;
use App\Support\Ciphertext;
use Database\Factories\VaultFileFactory;
use Illuminate\Contracts\Filesystem\Filesystem;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Storage;

/**
 * An encrypted file attachment.
 *
 * Named `VaultFile` rather than `File` for the table it maps to: `File` is a
 * Laravel facade and an `Illuminate\Http` class, and a model sharing that name
 * would make every `use` statement in a controller a small decision. The table
 * is still `files`, which is what docs/04-data-model.md describes.
 *
 * The row holds a manifest it cannot read and a pointer to a body it cannot
 * read either. Everything the server does with a file — bounding a chunk index,
 * counting bytes against a quota, noticing that an upload never finished — it
 * does from the metadata columns, and none of those say what the file is.
 *
 * @property int $id
 * @property string $uuid
 * @property int $lockbox_id
 * @property Ciphertext $payload_ct
 * @property Ciphertext $wrapped_item_key
 * @property int $payload_version
 * @property string $storage_key
 * @property string $storage_disk
 * @property int $chunk_count
 * @property string $received_chunks
 * @property int $ciphertext_size
 * @property ?Carbon $uploaded_at
 * @property int $sort_order
 * @property-read Lockbox $lockbox
 */
class VaultFile extends Model
{
    /** @use HasFactory<VaultFileFactory> */
    use HasFactory, SoftDeletes;

    protected $table = 'files';

    protected $fillable = [
        'uuid',
        'payload_ct',
        'wrapped_item_key',
        'payload_version',
        'storage_key',
        'storage_disk',
        'chunk_count',
        'received_chunks',
        'ciphertext_size',
        'uploaded_at',
        'sort_order',
    ];

    public function getRouteKeyName(): string
    {
        return 'uuid';
    }

    /**
     * Includes soft-deleted lockboxes, like Secret::lockbox(). The
     * authorisation chain has to have a parent to walk, and a deleted one is a
     * state to test rather than a null to trip over.
     *
     * @return BelongsTo<Lockbox, $this>
     */
    public function lockbox(): BelongsTo
    {
        return $this->belongsTo(Lockbox::class)->withTrashed();
    }

    public function chunks(): ChunkBitmap
    {
        return ChunkBitmap::fromBase64($this->received_chunks, $this->chunk_count);
    }

    public function isComplete(): bool
    {
        return $this->uploaded_at !== null;
    }

    public function disk(): Filesystem
    {
        return Storage::disk($this->storage_disk);
    }

    /**
     * Where one chunk lives.
     *
     * A directory named by the random `storage_key` with chunks numbered inside
     * it. No extension anywhere, and no part of the path derived from the
     * filename — the disk is not allowed to know what it is holding.
     */
    public function chunkPath(int $index): string
    {
        return "{$this->storage_key}/{$index}";
    }

    public function storageDirectory(): string
    {
        return $this->storage_key;
    }

    /**
     * @return array{uuid: string, lockboxUuid: string, payloadCt: string, wrappedItemKey: string, payloadVersion: int, chunkCount: int, ciphertextSize: int, uploadedAt: ?string, sortOrder: int, updatedAt: ?string}
     */
    public function toClientArray(): array
    {
        return [
            'uuid' => $this->uuid,
            'lockboxUuid' => $this->lockbox->uuid,
            'payloadCt' => $this->payload_ct->base64,
            'wrappedItemKey' => $this->wrapped_item_key->base64,
            'payloadVersion' => $this->payload_version,
            /*
             | Sent so the interface can show upload progress. The browser must
             | not build a chunk AAD from it — that number comes from the
             | manifest inside payload_ct, which is the copy the server cannot
             | change. See resources/js/lib/files.ts.
             */
            'chunkCount' => $this->chunk_count,
            'ciphertextSize' => $this->ciphertext_size,
            'uploadedAt' => $this->uploaded_at?->toIso8601String(),
            'sortOrder' => $this->sort_order,
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
            'uploaded_at' => 'datetime',
        ];
    }
}
