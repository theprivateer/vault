<?php

namespace App\Http\Controllers;

use App\Models\VaultFile;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\ValidationException;
use Symfony\Component\HttpFoundation\Response;

/**
 * The bodies of files, one chunk at a time.
 *
 * Everything crossing this controller is opaque. It checks three things about a
 * chunk — that it is not too big, that its two header bytes name an algorithm
 * this build writes, and that it belongs at the index it was sent to — and it
 * cannot check anything else, because it holds no key. That is the same
 * boundary `App\Rules\Envelope` draws for payloads, drawn again for a shape
 * that is not an envelope.
 *
 * Chunks are raw bytes rather than base64 in JSON. A payload is kilobytes and
 * the 33% overhead is irrelevant; a hundred-mebibyte file is the one place it
 * is not, and a chunk request has no other fields for JSON to be wrapping.
 */
class FileChunkController extends Controller
{
    /** Envelope version byte. Matches ENVELOPE_VERSION in crypto/envelope.ts. */
    private const VERSION = 1;

    /** AES-256-GCM. Matches ALG_AES_256_GCM in crypto/chunks.ts. */
    private const ALGORITHM = 2;

    /** ver + alg + GCM tag. A chunk of empty plaintext is still this long. */
    private const OVERHEAD_BYTES = 1 + 1 + 16;

    /**
     * Stores one chunk.
     *
     * **Writing a chunk whose bit is already set is a no-op that succeeds.**
     * That single rule buys two things at once. It makes the endpoint
     * idempotent, so a client that never saw the response to its last PUT can
     * simply send it again; and it makes a completed file immutable, so no
     * later request can replace part of a file other people have already
     * downloaded. Without it, `ciphertext_size` would also have to be a delta
     * rather than an addition, and quota accounting would drift every time a
     * retry landed.
     *
     * The row is locked before the bitmap is read, for the reason the re-key
     * endpoint locks before comparing an epoch: two chunks completing at once
     * would otherwise both read the same bitmap, and the second write would
     * erase the first's bit.
     */
    public function store(Request $request, VaultFile $file, int $index): JsonResponse
    {
        $chunk = $request->getContent();

        $this->assertIndexInRange($file, $index);
        $this->assertPlausibleChunk($chunk);

        $stored = DB::transaction(function () use ($file, $index, $chunk): bool {
            /** @var VaultFile $locked */
            $locked = VaultFile::query()->whereKey($file->getKey())->lockForUpdate()->firstOrFail();

            $bitmap = $locked->chunks();

            if ($bitmap->has($index)) {
                return false;
            }

            $this->assertWithinQuota($locked, strlen($chunk));

            $locked->disk()->put($locked->chunkPath($index), $chunk);

            $updated = $bitmap->with($index);

            $locked->forceFill([
                'received_chunks' => $updated->base64(),
                'ciphertext_size' => $locked->ciphertext_size + strlen($chunk),
                /*
                 | Set in the same transaction that sets the last bit, so
                 | "complete" and "every chunk present" can never disagree — a
                 | reader that saw one without the other would either refuse a
                 | whole file or serve a partial one.
                 */
                'uploaded_at' => $updated->isComplete() ? now() : null,
            ])->save();

            return true;
        });

        return response()->json([
            'stored' => $stored,
            'missingChunks' => $file->refresh()->chunks()->missing(),
            'uploadedAt' => $file->uploaded_at?->toIso8601String(),
        ]);
    }

    /**
     * Serves one chunk back.
     *
     * `no-store` because the response is the encrypted body of a private file
     * and there is no version of "a shared cache keeps a copy" that is wanted
     * here. It costs nothing: the client decrypts each chunk once and assembles
     * the result in memory.
     *
     * Incomplete files are refused. Half a file decrypts to half a file, and the
     * client would discover the gap only when a chunk request 404ed — a
     * confusing way to learn that an upload never finished.
     */
    public function show(VaultFile $file, int $index): Response
    {
        $this->assertIndexInRange($file, $index);

        if (! $file->isComplete()) {
            throw ValidationException::withMessages([
                'index' => 'This file has not finished uploading, so it cannot be downloaded yet.',
            ]);
        }

        $path = $file->chunkPath($index);

        abort_unless($file->disk()->exists($path), 404);

        return response($file->disk()->get($path), 200, [
            'Content-Type' => 'application/octet-stream',
            'Content-Length' => (string) $file->disk()->size($path),
            'Cache-Control' => 'no-store, private',
            /*
             | No filename, and no guess at one. The name is inside payload_ct
             | and the browser has already decrypted it — a Content-Disposition
             | here would be the server naming a file it cannot read.
             */
            'Content-Disposition' => 'attachment',
        ]);
    }

    private function assertIndexInRange(VaultFile $file, int $index): void
    {
        if ($index < 0 || $index >= $file->chunk_count) {
            throw ValidationException::withMessages([
                'index' => "Chunk {$index} is outside a file of {$file->chunk_count} chunks.",
            ]);
        }
    }

    /**
     * Shape and size only.
     *
     * The header check is the same downgrade guard `App\Rules\Envelope` applies
     * to payloads: a chunk naming an algorithm this build does not write is
     * rejected at the edge instead of being stored and failing in somebody's
     * browser months later.
     */
    private function assertPlausibleChunk(string $chunk): void
    {
        $maximum = Config::integer('vault.files.chunk_bytes') + self::OVERHEAD_BYTES;
        $length = strlen($chunk);

        if ($length < self::OVERHEAD_BYTES || $length > $maximum) {
            throw ValidationException::withMessages([
                'chunk' => "A chunk of {$length} bytes is not a plausible encrypted chunk.",
            ]);
        }

        if (ord($chunk[0]) !== self::VERSION || ord($chunk[1]) !== self::ALGORITHM) {
            throw ValidationException::withMessages([
                'chunk' => 'This chunk uses an envelope version or algorithm this build does not write.',
            ]);
        }
    }

    /**
     * Refuses a chunk that would take the vault past its quota.
     *
     * Counted in stored ciphertext rather than the plaintext size a client
     * declares, because that is the number the server can verify by weighing
     * what it has actually written. A declared size is a claim, and a quota
     * enforced against a claim is not a quota.
     *
     * Trashed files still count. Their bytes are still on the disk until the
     * purge sweep runs, and a quota that ignored them would let a vault hold
     * unbounded data by deleting and re-uploading.
     */
    private function assertWithinQuota(VaultFile $file, int $incoming): void
    {
        $quota = Config::integer('vault.files.quota_bytes');

        $used = (int) VaultFile::query()
            ->withTrashed()
            ->join('lockboxes', 'files.lockbox_id', '=', 'lockboxes.id')
            ->where('lockboxes.vault_id', $file->lockbox->vault_id)
            ->sum('files.ciphertext_size');

        if ($used + $incoming > $quota) {
            throw ValidationException::withMessages([
                'chunk' => 'This vault has no room left for file attachments. Delete something, or '
                    .'wait for deleted files to be purged, and try again.',
            ]);
        }
    }
}
