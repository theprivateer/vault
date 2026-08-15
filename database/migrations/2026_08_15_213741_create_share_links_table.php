<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * One-time share links: a single secret handed to somebody with no account.
 *
 * The recipient has no keys, so the link carries one. The browser re-encrypts
 * just that secret's payload under a fresh 32-byte link key and puts both the
 * key and a bearer token in the URL **fragment** — which is never sent to the
 * server, never written to an access log, and never placed in a `Referer`.
 *
 * `token_hash` is `BLAKE2b-256(token)`. The token itself is not stored, so a
 * stolen database cannot redeem a link any more than it can read one.
 *
 * **`payload_ct` here is encrypted under a key from outside the hierarchy.** It
 * is the only ciphertext in the schema not reachable from a Vault Key, and that
 * is the point: a share must not be openable with a vault key, or handing over
 * one secret would hand over the means to read the vault it came from. This is
 * the concrete reason the design gives every item its own key.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('share_links', function (Blueprint $table) {
            $table->id();
            $table->uuid('uuid')->unique();

            /*
             | The lookup key, and the only form of the token that exists here.
             |
             | `string` rather than the `text` every ciphertext column uses, and
             | the exception is deliberate: this is the one opaque value that is
             | *indexed*, and MySQL cannot put a unique index on a TEXT column
             | without a prefix length. It is a fixed 44 characters — base64 of a
             | 32-byte digest — so a varchar costs nothing and is portable.
             |
             | Unique because two links must not collide. At 32 random bytes the
             | constraint is really a guard against a bug in token generation
             | rather than against chance.
             */
            $table->string('token_hash', 64)->unique();

            $table->text('payload_ct');
            $table->unsignedSmallInteger('payload_version')->default(2);

            $table->foreignId('created_by')->constrained('users')->cascadeOnDelete();

            /*
             | Nulled rather than cascaded when the secret goes, deliberately:
             | the link keeps working. Its payload is a copy sealed under its own
             | key and owes nothing to the row it came from, and a link that died
             | because the sender tidied up afterwards would be a confusing way
             | to fail. Revoking is the way to end a link early.
             */
            $table->foreignId('secret_id')->nullable()->constrained()->nullOnDelete();

            $table->timestamp('expires_at');
            $table->unsignedSmallInteger('max_views')->default(1);
            $table->unsignedSmallInteger('view_count')->default(0);
            $table->timestamp('revoked_at')->nullable();

            $table->timestamp('created_at');

            /*
             | No `updated_at`. The only column that ever moves after creation is
             | `view_count`, and a timestamp beside it would record when a
             | stranger opened the link — which is exactly the kind of fact the
             | audit log should hold deliberately rather than a row should
             | accumulate by accident.
             */

            // The sweep's query: everything past its expiry, oldest first.
            $table->index('expires_at');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('share_links');
    }
};
