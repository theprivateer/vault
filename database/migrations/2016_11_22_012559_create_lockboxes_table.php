<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class CreateLockboxesTable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('lockboxes', function (Blueprint $table) {
            $table->increments('id');
            $table->uuid('uuid');
            $table->unsignedInteger('vault_id');
            $table->foreign('vault_id')->references('id')->on('vaults')->onDelete('cascade');
            $table->string('name');
            $table->text('description')->nullable()->default(null);
            $table->text('notes')->nullable()->default(null);
            $table->boolean('control')->default(false);
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('lockboxes');
    }
}
