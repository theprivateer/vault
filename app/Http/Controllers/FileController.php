<?php

namespace App\Http\Controllers;

use App\Enums\AuditAction;
use App\Http\Requests\StoreFileRequest;
use App\Models\Lockbox;
use App\Models\VaultFile;
use App\Support\AuditLog;
use App\Support\ChunkBitmap;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Str;

/**
 * File attachments: the row, not the body. Chunks are FileChunkController.
 *
 * In 2017 an upload was written to disk under a name built from the file's own,
 * and the row recorded `original_name`, `file_type` and `extension` in the
 * clear. Here the name and type are inside `payload_ct` and the object is keyed
 * by a random UUID with no extension, so nothing on the disk or in these
 * columns says what any of it is.
 */
class FileController extends Controller
{
    /**
     * Creates the row, before a single byte of the body arrives.
     *
     * This ordering is the whole resume story. The wrapped File Key is written
     * here, so a transfer interrupted by a closed tab can be finished later
     * against the same key and the same nonces; without it the client would
     * have to start again from a fresh key, and "resumable" would mean
     * "restartable".
     *
     * `storage_key` is generated *here* rather than accepted. A client-chosen
     * object name is a path the client controls, and the only reason this
     * identifier exists is to be unguessable and to say nothing.
     */
    public function store(StoreFileRequest $request, Lockbox $lockbox): RedirectResponse
    {
        $chunkCount = $request->integer('chunk_count');

        $file = $lockbox->files()->create([
            'uuid' => $request->string('uuid')->toString(),
            'payload_ct' => $request->string('payload_ct')->toString(),
            'wrapped_item_key' => $request->string('wrapped_item_key')->toString(),
            'payload_version' => $request->integer('payload_version'),
            'storage_key' => (string) Str::uuid7(),
            'storage_disk' => Config::string('vault.files.disk'),
            'chunk_count' => $chunkCount,
            'received_chunks' => ChunkBitmap::empty($chunkCount)->base64(),
            'ciphertext_size' => 0,
            'sort_order' => $request->integer('sort_order'),
        ]);

        AuditLog::record(AuditAction::FileCreated, $file, ['chunk_count' => $chunkCount]);

        return back();
    }

    /**
     * What the server is still waiting for.
     *
     * Answers with chunk indices rather than a count, because a resumed upload
     * needs to know *which* are missing — chunks are independent PUTs and can
     * land out of order, so "37 received" does not identify the gap.
     */
    public function status(VaultFile $file): JsonResponse
    {
        return response()->json([
            'uuid' => $file->uuid,
            'chunkCount' => $file->chunk_count,
            'missingChunks' => $file->chunks()->missing(),
            'uploadedAt' => $file->uploaded_at?->toIso8601String(),
        ]);
    }

    /**
     * Soft-deletes the row. The bytes stay until the purge sweep.
     *
     * Deliberately reversible for the grace period, exactly like a secret. The
     * objects are removed by `vault:files-prune`, which is also the only thing
     * that ever hard-deletes them — a delete route that unlinked immediately
     * would make an accidental click permanent, and there is no copy of a file
     * anywhere else.
     */
    public function destroy(VaultFile $file): RedirectResponse
    {
        AuditLog::record(AuditAction::FileDeleted, $file, ['bytes' => $file->ciphertext_size]);

        $file->delete();

        return back();
    }
}
