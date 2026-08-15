<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * File attachments (Phase 6).
 *
 * The 2017 table carried `original_name`, `file_type` and `extension` as
 * plaintext columns, and wrote the upload to disk under a name derived from
 * them. All three are inside `payload_ct` here, together with the chunk count,
 * the chunk size, the plaintext hash and the nonce prefix — everything a reader
 * needs and the server has no use for.
 *
 * What is left in the clear is what the server has to act on: which lockbox owns
 * the row, how many chunks it should receive, which ones have arrived, and how
 * many bytes it is holding. Between them those leak the size of a file to within
 * a chunk, which is written down as accepted in docs/02-threat-model.md — a file
 * body is far too large to pad the way a payload is.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('files', function (Blueprint $table) {
            $table->id();
            $table->uuid('uuid')->unique();
            $table->foreignId('lockbox_id')->constrained()->cascadeOnDelete();

            // {filename, mime, sha256, chunkCount, chunkSize, plaintextSize,
            //  noncePrefix}. The manifest, and the only description of the file
            //  that exists anywhere.
            $table->text('payload_ct');
            $table->text('wrapped_item_key');
            $table->unsignedSmallInteger('payload_version')->default(1);

            /*
             | Where the body lives. A random UUID with no extension and no
             | relationship to the filename, so a directory listing of the disk
             | says nothing at all. Chunks are objects beneath it, named by
             | index.
             */
            $table->uuid('storage_key')->unique();
            $table->string('storage_disk');

            /*
             | The server's copy of the chunk count, used to bound an index and
             | to know when an upload is complete.
             |
             | The client never builds an AAD from it — that value comes from
             | the manifest, which the server cannot read. A server that could
             | shrink the count a client verified against could truncate a file
             | undetectably, which is the whole reason the count is bound into
             | each chunk's associated data in the first place.
             */
            $table->unsignedInteger('chunk_count');

            /*
             | A bitmap, one bit per chunk, of what has arrived. Base64 in text
             | like every other blob here.
             |
             | A counter would be smaller and would be wrong: chunks are
             | idempotent PUTs, so a retry of one already stored would advance a
             | counter twice and declare an incomplete file finished.
             */
            $table->text('received_chunks');

            /** Bytes actually written to disk. Weighed, not declared — quotas. */
            $table->unsignedBigInteger('ciphertext_size')->default(0);

            /*
             | Null until every chunk has landed. An incomplete file is not
             | downloadable and is what the orphan sweep looks for.
             */
            $table->timestamp('uploaded_at')->nullable();

            $table->integer('sort_order')->default(0);

            $table->timestamps();
            $table->softDeletes();

            $table->index(['lockbox_id', 'sort_order']);
            // The orphan sweep: incomplete uploads, oldest first.
            $table->index(['uploaded_at', 'created_at']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('files');
    }
};
