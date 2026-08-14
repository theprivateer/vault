<?php

use App\Http\Controllers\Auth\KdfParamsController;
use App\Http\Controllers\Auth\LoginController;
use App\Http\Controllers\Auth\RecoveryController;
use App\Http\Controllers\Auth\RegisterController;
use App\Http\Controllers\Auth\TotpController;
use App\Http\Controllers\VaultController;
use Illuminate\Support\Facades\Route;
use Inertia\Inertia;

Route::redirect('/', '/vault')->name('home');

Route::middleware('guest')->group(function (): void {
    // Registration is invite-only (D11). There is no open sign-up route.
    Route::get('/register/{token}', [RegisterController::class, 'create'])->name('register');
    Route::post('/register/{token}', [RegisterController::class, 'store'])
        ->middleware('throttle:6,1');

    Route::get('/login', [LoginController::class, 'create'])->name('login');
    Route::post('/login', [LoginController::class, 'store'])->name('login.store');

    Route::post('/auth/kdf-params', KdfParamsController::class)
        ->name('auth.kdf-params')
        ->middleware('throttle:kdf-params');

    Route::get('/recover', [RecoveryController::class, 'create'])->name('recover');
    Route::post('/recover/salt', [RecoveryController::class, 'salt'])
        ->name('recover.salt')
        ->middleware('throttle:kdf-params');
    Route::post('/recover', [RecoveryController::class, 'store'])->name('recover.store');

    /*
     | There is no password reset, and there cannot be: the server cannot
     | re-wrap a User Key it is unable to unwrap. This page explains that rather
     | than leaving a dead link.
     */
    Route::get('/forgot-password', fn () => Inertia::render('auth/NoPasswordReset'))
        ->name('password.request');
});

Route::middleware('auth')->group(function (): void {
    Route::post('/logout', [LoginController::class, 'destroy'])->name('logout');

    Route::get('/vault', [VaultController::class, 'index'])->name('vault');

    Route::post('/account/password', [RecoveryController::class, 'update'])->name('password.update');
    Route::post('/account/recovery-kit', [RecoveryController::class, 'reissue'])
        ->name('recovery-kit.reissue');

    Route::get('/account/two-factor', [TotpController::class, 'create'])->name('totp.create');
    Route::post('/account/two-factor', [TotpController::class, 'store'])->name('totp.store');
    Route::delete('/account/two-factor', [TotpController::class, 'destroy'])->name('totp.destroy');
});
