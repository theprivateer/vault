<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * When a vault's key last changed, and how often it would like to be reminded.
 *
 * `key_epoch` already says how many times a vault has rotated; it does not say
 * *when*, and `updated_at` moves for a rename. Without a column that means only
 * this, "has this key been the same since 2026" is a question the operator
 * cannot ask — which is the difference between rotation as a routine operation
 * and rotation as something that happens after an incident (Phase 10).
 *
 * **The server cannot rotate on a schedule**, so `rotate_after_days` is a
 * reminder rather than a job. Rotation needs a member's browser: only a member
 * can unwrap the current Vault Key, and nothing here ever holds it. A cron entry
 * that claimed to rotate vaults would be claiming a capability this design
 * spent nine phases not having.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('vaults', function (Blueprint $table): void {
            $table->timestamp('key_rotated_at')->nullable()->after('rekey_required_at');

            /*
             | Null means "whatever the deployment's default is", exactly as the
             | history columns do. Zero is a real answer and means "never remind
             | me" — a vault whose key protects something that does not change is
             | not made safer by a badge.
             */
            $table->unsignedSmallInteger('rotate_after_days')->nullable()->after('key_rotated_at');
        });

        /*
         | Existing vaults get their creation time, which is the truth: their key
         | is as old as they are unless a re-key has happened, and a re-key
         | writes this column from now on. Leaving it null would have made every
         | vault read as "never rotated", which is the same word for "brand new"
         | and "eight years untouched".
         */
        DB::table('vaults')->update(['key_rotated_at' => DB::raw('created_at')]);
    }

    public function down(): void
    {
        Schema::table('vaults', function (Blueprint $table): void {
            $table->dropColumn(['key_rotated_at', 'rotate_after_days']);
        });
    }
};
