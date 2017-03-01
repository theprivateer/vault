<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class AddControlColumnToVault extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::table('vaults', function (Blueprint $table) {
            $table->text('control')->nullable()->default(null)->after('description');
            $table->dropColumn(['use_passkey', 'passkey_reminder']);
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::table('vaults', function (Blueprint $table) {
            $table->dropColumn('control');
            $table->text('passkey_reminder')->nullable()->default(null)->after('description');
            $table->boolean('use_passkey')->default(false)->after('description');
        });
    }
}
