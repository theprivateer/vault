<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Identities that have been retired, and the certificates that retired them.
 *
 * **Public halves only.** The private keys are discarded at the moment a
 * rotation lands, which is the point of rotating — keeping them here would turn
 * "I replaced a key I no longer trust" into "I replaced a key I no longer trust
 * and left it on the server". Everything that was sealed to the old public key
 * is re-sealed to the new one in the same request, so nothing needs them.
 *
 * Two jobs, and they are different:
 *
 * 1. **The rotation certificate**, signed by the key being retired, so a peer
 *    holding the old fingerprint can tell "they rotated" from "the server
 *    substituted its own key". Those arrive identically otherwise, and a person
 *    shown the same red screen for both learns to click through it.
 * 2. **The retired fingerprint**, so the owner's own client can still verify
 *    grants issued to them before the rotation. A grant names the fingerprint it
 *    was issued for; without a record of past identities, rotating would make
 *    every vault somebody shared with you render as unverifiable.
 *
 * `rotation_payload` is stored byte-exact as text for the same reason
 * `vault_memberships.grant_payload` is: a signature verifies over bytes, and any
 * round trip through a JSON codec is free to change them.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('user_identity_archive', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->constrained()->cascadeOnDelete();

            // The retired keys. A peer recomputes their fingerprint from these
            // and compares it against their own pin before believing the
            // certificate — a certificate checked against a key the server
            // supplied would be the forger checking the forgery.
            $table->text('x25519_public_key');
            $table->text('ed25519_public_key');
            $table->text('self_signature');
            $table->text('fingerprint');

            // Signed by the retired Ed25519 key, naming its successor. Text
            // rather than json: never cast, never re-encoded.
            $table->text('rotation_payload');
            $table->text('rotation_signature');

            $table->timestamp('rotated_at');
            $table->timestamps();

            // "The most recent identity this user retired" is the only query.
            $table->index(['user_id', 'rotated_at']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('user_identity_archive');
    }
};
