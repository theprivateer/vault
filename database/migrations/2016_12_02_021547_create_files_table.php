<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class CreateFilesTable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('files', function (Blueprint $table) {
            $table->increments('id');
            $table->uuid('uuid');
            $table->unsignedInteger('lockbox_id');
            $table->foreign('lockbox_id')->references('id')->on('lockboxes')->onDelete('cascade');
            $table->string('file_name');
            $table->string('original_name');
            $table->string('file_type')->nullable()->default(null);
            $table->string('extension')->nullable()->default(null);
            $table->double('size')->default(0);
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
        Schema::dropIfExists('files');
    }
}
