<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * The framework's default users table is replaced wholesale.
     *
     * There is deliberately no `password` column: the server never receives a
     * password. It receives an auth key derived from one, and stores only a slow
     * hash of that. Nothing on this table can decrypt anything.
     *
     * `password_reset_tokens` is also absent — see the note in
     * docs/04-data-model.md. The server cannot re-wrap a User Key it cannot
     * unwrap, so there is no reset flow to support, and an empty table would
     * only invite someone to wire one up.
     */
    public function up(): void
    {
        Schema::create('users', function (Blueprint $table) {
            $table->id();
            $table->uuid('uuid')->unique();
            $table->string('email')->unique();
            $table->string('display_name');
            $table->string('handle')->unique();

            // Not secret, and must be fetchable before authentication so the
            // client can derive its keys. See the decoy-salt note on the
            // kdf-params endpoint.
            $table->string('kdf_salt');
            $table->string('kdf_algorithm')->default('argon2id');
            $table->json('kdf_params');

            // Argon2id over the auth key. Slow on purpose: the auth key inherits
            // only the password's entropy, not 256 bits.
            $table->string('auth_key_hash');

            $table->text('totp_secret_ct')->nullable();
            $table->timestamp('totp_confirmed_at')->nullable();

            $table->timestamp('recovery_used_at')->nullable();
            $table->timestamp('last_login_at')->nullable();

            $table->rememberToken();
            $table->timestamps();
        });

        Schema::create('sessions', function (Blueprint $table) {
            $table->string('id')->primary();
            $table->foreignId('user_id')->nullable()->index();
            $table->string('ip_address', 45)->nullable();
            $table->text('user_agent')->nullable();
            $table->longText('payload');
            $table->integer('last_activity')->index();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('users');
        Schema::dropIfExists('sessions');
    }
};
