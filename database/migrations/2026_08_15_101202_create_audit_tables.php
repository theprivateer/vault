<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * The tamper-evident audit log (Phase 7).
 *
 * This is the main compensating control for everything the server cannot see.
 * It cannot read a secret, so it cannot tell you *what* was taken — but it can
 * tell you that somebody's session opened forty items in a minute at three in
 * the morning, and it can make quietly deleting that record detectable.
 *
 * Each row's hash covers the previous row's hash, so the table is a chain rather
 * than a list. Modifying a row, deleting one, or reordering two all break every
 * hash after the change, and `vault:audit-verify` reports the first `seq` that
 * diverges.
 *
 * **What this does and does not defend against.** The server writes these rows,
 * so a compromised server can rewrite the entire chain from any point and
 * recompute every hash after it — the chain alone only stops *careless* or
 * *partial* tampering. Two things make it harder: client-originated events carry
 * an Ed25519 signature the server cannot forge, and the chain head is mailed to
 * the operator daily, so a rewritten chain contradicts a record the server never
 * had. Both are honest hardenings rather than a solution, and
 * docs/02-threat-model.md says so.
 */
return new class extends Migration
{
    public function up(): void
    {
        /*
         | The chain tip: one row, forever.
         |
         | It exists so that allocating `seq` has something to lock. The obvious
         | alternative — `SELECT ... ORDER BY seq DESC LIMIT 1 FOR UPDATE` on the
         | events themselves — is racy for inserts: a blocked transaction rechecks
         | the row it was waiting on, not the *new* maximum, so two writers both
         | compute the same next sequence. Locking a row that always exists has no
         | such window, and it makes reading the head an O(1) lookup for the daily
         | anchor rather than an index scan.
         |
         | The unique index on `audit_events.seq` is the backstop underneath: if
         | this lock is ever bypassed, the second insert fails loudly instead of
         | forking the chain.
         */
        Schema::create('audit_chain', function (Blueprint $table) {
            $table->id();

            // 0 before anything is recorded, so the genesis entry is seq 1.
            $table->unsignedBigInteger('seq')->default(0);

            // 32 zero bytes until the first entry. Base64 in text, like every
            // other blob here — see .ai/rules/migrations.md.
            $table->text('head_hash');

            $table->timestamp('updated_at')->nullable();
        });

        DB::table('audit_chain')->insert([
            'id' => 1,
            'seq' => 0,
            'head_hash' => base64_encode(str_repeat("\0", 32)),
            'updated_at' => now(),
        ]);

        Schema::create('audit_events', function (Blueprint $table) {
            $table->id();

            /*
             | Gapless, allocated under the lock above. Gapless rather than merely
             | increasing because a gap is the signature of a deleted row, and a
             | log where deletion is invisible is not an audit log.
             */
            $table->unsignedBigInteger('seq')->unique();

            $table->text('prev_hash');
            $table->text('hash');

            /*
             | Who did it, by UUID and **not** by foreign key.
             |
             | A nullable FK with `nullOnDelete` would mean deleting a user
             | silently rewrites every row they ever touched — which changes the
             | bytes those rows were hashed over and breaks the chain from the
             | earliest of them onward. The log would then report tampering
             | because somebody closed their account. Nothing else may edit these
             | rows, so nothing else may either, including a cascade.
             |
             | Null for events with no human behind them: a scheduled sweep, or a
             | failed login against an address that belongs to nobody.
             */
            $table->uuid('actor_uuid')->nullable();

            $table->string('action');

            // Polymorphic by UUID rather than by foreign key: the subject may be
            // hard-deleted later, and the record of what happened to it must
            // outlive it. A cascade here would let deleting a vault erase its
            // own history.
            $table->string('subject_type')->nullable();
            $table->uuid('subject_uuid')->nullable();

            /*
             | Structural facts only — a role, a count, an epoch. Never payload
             | content, which is the obvious way this table quietly becomes the
             | plaintext leak the whole design exists to prevent.
             |
             | `text` holding canonical JSON, not `json`: the hash covers these
             | bytes exactly as stored, and a column type that reordered keys or
             | normalised whitespace would invalidate the chain from that row on.
             | Same trap as `vault_memberships.grant_payload`.
             */
            $table->text('metadata');

            /*
             | Ed25519 over the event, by the acting user's key, for events the
             | browser reports rather than the server observes. The server cannot
             | forge one, so these survive a compromise of the server that the
             | chain alone does not.
             */
            $table->text('actor_signature')->nullable();
            $table->text('signed_payload')->nullable();

            /*
             | HMAC, not the address. Enough to correlate "the same origin came
             | back" without the log becoming a record of where somebody lives.
             | Keyed with APP_KEY, so a stolen database does not yield a rainbow
             | table over the IPv4 space — which an unkeyed hash would.
             */
            $table->text('ip_hash')->nullable();
            $table->text('user_agent_hash')->nullable();

            /*
             | No `updated_at`, deliberately. There is no update route, the model
             | refuses to be updated or deleted, and in production the application
             | role is denied UPDATE and DELETE on this table:
             |
             |   REVOKE UPDATE, DELETE ON audit_events FROM vault_app;
             |
             | Three layers because the first two are code that a future change
             | can undo, and the third is not.
             */
            $table->timestamp('created_at');

            $table->index(['subject_type', 'subject_uuid']);
            $table->index(['actor_uuid', 'id']);
            $table->index('action');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('audit_events');
        Schema::dropIfExists('audit_chain');
    }
};
