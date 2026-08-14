<?php

use App\Http\Controllers\Auth\KdfParamsController;
use App\Http\Controllers\Auth\LoginController;
use App\Http\Controllers\Auth\RecoveryController;
use App\Http\Controllers\Auth\RegisterController;
use App\Http\Controllers\Auth\TotpController;
use App\Http\Controllers\LockboxController;
use App\Http\Controllers\SecretController;
use App\Http\Controllers\VaultController;
use Illuminate\Support\Facades\Route;
use Inertia\Inertia;

Route::redirect('/', '/vaults')->name('home');

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

    /*
     | Every parent is a route parameter, never a request field. A lockbox is
     | created *inside* a vault the router has already resolved and a policy has
     | already checked; a secret is created inside a lockbox the same way. There
     | is no endpoint that takes a parent identifier in a body, so there is no
     | endpoint where one could be swapped.
     |
     | Authorisation is `can:` middleware rather than a call inside the
     | controller, because middleware runs *before* the form request is
     | resolved. With the check in the controller, an unauthorised write to a
     | real record failed validation first and answered 302 with errors, while
     | an unknown identifier answered 404 — telling an attacker which UUIDs
     | exist, which is exactly what the 404-not-403 rule exists to prevent.
     | Found by the IDOR suite in tests/Feature/Vault/AuthorisationTest.php.
     */
    Route::get('/vaults', [VaultController::class, 'index'])->name('vaults.index');
    Route::post('/vaults', [VaultController::class, 'store'])->name('vaults.store');

    Route::middleware('can:view,vault')->group(function (): void {
        Route::get('/vaults/{vault}', [VaultController::class, 'show'])->name('vaults.show');
    });

    Route::middleware('can:update,vault')->group(function (): void {
        Route::patch('/vaults/{vault}', [VaultController::class, 'update'])->name('vaults.update');
        Route::post('/vaults/{vault}/lockboxes', [LockboxController::class, 'store'])
            ->name('lockboxes.store');
    });

    Route::delete('/vaults/{vault}', [VaultController::class, 'destroy'])
        ->middleware('can:delete,vault')
        ->name('vaults.destroy');

    Route::get('/lockboxes/{lockbox}', [LockboxController::class, 'show'])
        ->middleware('can:view,lockbox')
        ->name('lockboxes.show');

    Route::middleware('can:update,lockbox')->group(function (): void {
        Route::patch('/lockboxes/{lockbox}', [LockboxController::class, 'update'])
            ->name('lockboxes.update');
        Route::post('/lockboxes/{lockbox}/secrets', [SecretController::class, 'store'])
            ->name('secrets.store');
    });

    Route::delete('/lockboxes/{lockbox}', [LockboxController::class, 'destroy'])
        ->middleware('can:delete,lockbox')
        ->name('lockboxes.destroy');

    Route::patch('/secrets/{secret}', [SecretController::class, 'update'])
        ->middleware('can:update,secret')
        ->name('secrets.update');

    Route::delete('/secrets/{secret}', [SecretController::class, 'destroy'])
        ->middleware('can:delete,secret')
        ->name('secrets.destroy');

    Route::post('/account/password', [RecoveryController::class, 'update'])->name('password.update');
    Route::post('/account/recovery-kit', [RecoveryController::class, 'reissue'])
        ->name('recovery-kit.reissue');

    Route::get('/account/two-factor', [TotpController::class, 'create'])->name('totp.create');
    Route::post('/account/two-factor', [TotpController::class, 'store'])->name('totp.store');
    Route::delete('/account/two-factor', [TotpController::class, 'destroy'])->name('totp.destroy');
});
