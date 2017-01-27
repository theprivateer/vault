<?php

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| This file is where you may define all of the routes that are handled
| by your application. Just tell Laravel the URIs it should respond
| to using a Closure or controller method. Build something great!
|
*/
Route::get('/', function() {
    return (config('vault.splash_page')) ? view('home') : redirect()->route('lockbox.index');
});

Route::get('test', function() {
   return view('test');
});

Auth::routes();

Route::group(['middleware' => 'auth'], function() {

    Route::get('user', [
        'uses'  => 'UserController@edit',
        'as'    => 'user.edit'
    ]);

    Route::post('user', [
        'uses'  => 'UserController@update',
        'as'    => 'user.edit'
    ]);

    Route::group(['namespace' => 'Lockboxes'], function() {

        Route::get('/home', [
            'uses'  => 'LockboxController@index',
            'as'    => 'lockbox.index'
        ]);

        Route::get('lockbox/create', [
            'uses'  => 'LockboxController@create',
            'as'    => 'lockbox.create'
        ]);

        Route::post('lockbox/create', [
            'uses'  => 'LockboxController@store',
            'as'    => 'lockbox.create'
        ]);

        Route::get('lockbox/{uuid}', [
            'uses'  => 'LockboxController@show',
            'as'    => 'lockbox.show'
        ]);

        Route::get('lockbox/{uuid}/edit', [
            'uses'  => 'LockboxController@edit',
            'as'    => 'lockbox.edit'
        ]);

        Route::post('lockbox/{uuid}/edit', [
            'uses'  => 'LockboxController@update',
            'as'    => 'lockbox.edit'
        ]);

        Route::post('lockbox/{uuid}/move', [
            'uses'  => 'LockboxController@move',
            'as'    => 'lockbox.move'
        ]);

        Route::delete('lockbox', [
            'uses'  => 'LockboxController@destroy',
            'as'    => 'lockbox.destroy'
        ]);

        Route::get('lockbox/{uuid}/secrets', [
            'uses'  => 'SecretController@edit',
            'as'    => 'secret.edit'
        ]);

        Route::post('lockbox/{uuid}/secrets', [
            'uses'  => 'SecretController@update',
            'as'    => 'secret.edit'
        ]);

        Route::get('lockbox/{uuid}/file', [
            'uses'  => 'FileController@edit',
            'as'    => 'file.edit'
        ]);

        Route::post('lockbox/{uuid}/file', [
            'uses'  => 'FileController@update',
            'as'    => 'file.edit'
        ]);

        Route::post('lockbox/{uuid}/file/store', [
            'uses'  => 'FileController@store',
            'as'    => 'file.store'
        ]);

        Route::get('file/{hash}', [
            'uses'  => 'FileController@show',
            'as'    => 'file.show'
        ]);

        Route::delete('file', [
            'uses'  => 'FileController@destroy',
            'as'    => 'file.destroy'
        ]);
    });

    Route::group(['namespace' => 'Vaults'], function() {
        Route::get('vaults', [
            'uses'  => 'VaultController@index',
            'as'    => 'vault.index'
        ]);

        Route::get('vault/create', [
            'uses'  => 'VaultController@create',
            'as'    => 'vault.create'
        ]);

        Route::post('vault/create', [
            'uses'  => 'VaultController@store',
            'as'    => 'vault.create'
        ]);

        Route::get('vault/{uuid}', [
            'uses'  => 'VaultController@show',
            'as'    => 'vault.show'
        ]);

        Route::get('vault/{uuid}/edit', [
            'uses'  => 'VaultController@edit',
            'as'    => 'vault.edit'
        ]);

        Route::post('vault/{uuid}/edit', [
            'uses'  => 'VaultController@update',
            'as'    => 'vault.edit'
        ]);

        Route::delete('vault', [
            'uses'  => 'VaultController@destroy',
            'as'    => 'vault.destroy'
        ]);


        Route::post('vault/{uuid}/user', [
           'uses'   => 'UserController@store',
            'as'    => 'vault.user.add'
        ]);

        Route::post('vault/{uuid}/user/edit', [
            'uses'   => 'UserController@update',
            'as'    => 'vault.user.edit'
        ]);

        Route::delete('vault/{uuid}/user', [
            'uses'   => 'UserController@destroy',
            'as'    => 'vault.user.destroy'
        ]);
    });
});