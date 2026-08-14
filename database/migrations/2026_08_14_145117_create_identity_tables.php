<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        /*
         | The unlock methods that can recover a user's User Key.
         |
         | A table rather than columns on `users` because the set is open-ended:
         | adding passkey (WebAuthn PRF) unlock later becomes a new row, not a
         | migration of the auth flow. See docs/04-data-model.md.
         */
        Schema::create('user_key_wraps', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->constrained()->cascadeOnDelete();
            $table->string('method');
            $table->text('wrapped_user_key');
            $table->text('salt')->nullable();

            /*
             | For the recovery method: a hash of the recovery *auth* key, which
             | is derived from the recovery code independently of the KEK that
             | unwraps the User Key.
             |
             | This lets the server verify a recovery attempt — so an attacker
             | cannot overwrite someone's password wrapping, and the recovery
             | wrapping is not handed to anyone who names an address — without
             | learning anything that opens the User Key. Sending the code
             | itself would give a server that already holds the wrapped key
             | everything it needs.
             */
            $table->string('verifier_hash')->nullable();
            $table->string('label')->nullable();
            $table->timestamp('last_used_at')->nullable();
            $table->timestamps();

            $table->unique(['user_id', 'method', 'label']);
        });

        /*
         | Public keys are served by the server, which means the server can lie
         | about them. The self-signature proves both keys were published
         | together by whoever holds the Ed25519 private key; the fingerprint is
         | what a human compares out of band. Neither makes this table a root of
         | trust — the out-of-band comparison is.
         */
        Schema::create('user_identities', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->unique()->constrained()->cascadeOnDelete();

            $table->text('x25519_public_key');
            $table->text('ed25519_public_key');
            $table->text('x25519_private_key_ct');
            $table->text('ed25519_private_key_ct');
            $table->text('self_signature');
            $table->text('fingerprint');

            $table->timestamp('rotated_at')->nullable();
            $table->timestamps();
        });

        /*
         | Registration is invite-only (D11). The invite carries no key material:
         | it authorises account creation and nothing more.
         */
        Schema::create('invites', function (Blueprint $table) {
            $table->id();
            $table->uuid('uuid')->unique();
            $table->string('email')->index();
            $table->string('token_hash')->unique();
            $table->foreignId('invited_by')->nullable()->constrained('users')->nullOnDelete();
            $table->timestamp('expires_at');
            $table->timestamp('accepted_at')->nullable();
            $table->timestamps();
        });

        /*
         | Single-use recovery codes for the TOTP second factor. Hashed, because
         | the server has no reason to be able to read them back.
         |
         | Distinct from the recovery *kit*, which never touches the server.
         */
        Schema::create('totp_backup_codes', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->constrained()->cascadeOnDelete();
            $table->string('code_hash');
            $table->timestamp('used_at')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('totp_backup_codes');
        Schema::dropIfExists('invites');
        Schema::dropIfExists('user_identities');
        Schema::dropIfExists('user_key_wraps');
    }
};
