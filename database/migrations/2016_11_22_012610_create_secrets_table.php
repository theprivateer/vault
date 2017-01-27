<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class CreateSecretsTable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('secrets', function (Blueprint $table) {
            $table->increments('id');
            $table->uuid('uuid');
            $table->unsignedInteger('lockbox_id');
            $table->foreign('lockbox_id')->references('id')->on('lockboxes')->onDelete('cascade');
            $table->text('key');
            $table->text('value')->nullable()->default(null);
            $table->integer('linked_lockbox_id')->unsigned()->default(0);
            $table->boolean('paranoid')->default(false);
            $table->integer('sort_order')->unsigned()->default(0);
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
        Schema::dropIfExists('secrets');
    }
}
