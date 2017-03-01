<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class RemoveControlLockboxes extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        \Illuminate\Support\Facades\DB::table('lockboxes')->where('control', true)->delete();

        Schema::table('lockboxes', function (Blueprint $table) {
            $table->dropColumn('control');
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::table('lockboxes', function (Blueprint $table) {
            //
        });
    }
}
