<?php

use App\Http\Controllers\AuditEventController;
use App\Http\Controllers\Auth\KdfParamsController;
use App\Http\Controllers\Auth\KdfUpgradeController;
use App\Http\Controllers\Auth\LoginController;
use App\Http\Controllers\Auth\RecoveryController;
use App\Http\Controllers\Auth\RegisterController;
use App\Http\Controllers\Auth\TotpController;
use App\Http\Controllers\FileChunkController;
use App\Http\Controllers\FileController;
use App\Http\Controllers\IdentityRotationController;
use App\Http\Controllers\LockboxController;
use App\Http\Controllers\PinStoreController;
use App\Http\Controllers\SecretController;
use App\Http\Controllers\SecretHistoryController;
use App\Http\Controllers\ShareLinkController;
use App\Http\Controllers\UserIdentityController;
use App\Http\Controllers\VaultController;
use App\Http\Controllers\VaultMembershipController;
use App\Http\Controllers\VaultOwnershipController;
use App\Http\Controllers\VaultRekeyController;
use App\Http\Controllers\VaultResealController;
use App\Http\Controllers\VaultRetentionController;
use Illuminate\Support\Facades\Route;
use Inertia\Inertia;

Route::redirect('/', '/vaults')->name('home');

/*
 | One-time share links (Phase 9).
 |
 | Outside both `auth` and `guest`: a link is for whoever holds it, which may be
 | a stranger with no account or may be a colleague who happens to be signed in.
 |
 | **Neither route carries the token.** It lives in the URL fragment beside the
 | link key, so `GET /s` serves an empty page and the browser posts the token to
 | `/s/reveal` in a request body. A path segment would have been written to every
 | access log in front of this application in the clear, which would make the
 | security requirement that no log holds a token unachievable rather than
 | merely untested. It also means a chat client unfurling the link fetches a page
 | with no token in it and therefore cannot consume the single view.
 |
 | Throttled hard. This is the one unauthenticated endpoint that reads from the
 | database by a secret value, so it is the one place a guessing attempt would
 | go — 32 random bytes make that hopeless, but a rate limit turns hopeless into
 | not worth attempting.
 */
Route::get('/s', [ShareLinkController::class, 'show'])->name('share.show');
Route::post('/s/reveal', [ShareLinkController::class, 'reveal'])
    ->middleware('throttle:20,1')
    ->name('share.reveal');

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

    /*
     | Audit (Phase 7).
     |
     | The reporting endpoint accepts only the two actions the server cannot
     | observe for itself, each carrying an Ed25519 signature over the exact
     | bytes stored. Throttled because it is the one write path a page can call
     | freely — a reveal is a click, and a log nobody can read because one
     | session filled it is a log that has failed at its job.
     */
    Route::post('/audit', [AuditEventController::class, 'store'])
        ->middleware('throttle:120,1')
        ->name('audit.store');

    Route::get('/account/activity', [AuditEventController::class, 'mine'])->name('audit.mine');

    /*
     | Links this user can withdraw: their own, plus any issued into a vault they
     | administer. Account-scoped rather than per-vault because the question it
     | answers — "what have I left outstanding?" — spans vaults, and because a
     | link whose secret has been deleted has no vault to be listed under.
     */
    Route::get('/account/links', [ShareLinkController::class, 'index'])->name('links.index');

    Route::post('/vaults', [VaultController::class, 'store'])->name('vaults.store');

    Route::middleware('can:view,vault')->group(function (): void {
        Route::get('/vaults/{vault}', [VaultController::class, 'show'])->name('vaults.show');
        Route::get('/vaults/{vault}/activity', [AuditEventController::class, 'vault'])
            ->name('vaults.activity');
    });

    Route::middleware('can:update,vault')->group(function (): void {
        Route::patch('/vaults/{vault}', [VaultController::class, 'update'])->name('vaults.update');
        Route::post('/vaults/{vault}/lockboxes', [LockboxController::class, 'store'])
            ->name('lockboxes.store');
    });

    Route::delete('/vaults/{vault}', [VaultController::class, 'destroy'])
        ->middleware('can:delete,vault')
        ->name('vaults.destroy');

    /*
     | How long the vault keeps superseded payloads (Phase 8). An administrator
     | ability rather than a write one — shortening it destroys history for
     | everybody in the vault, and lengthening it leaves everybody's old
     | credentials on the server for longer.
     */
    Route::patch('/vaults/{vault}/history', [VaultRetentionController::class, 'update'])
        ->middleware('can:configure,vault')
        ->name('vaults.history.update');

    /*
     | Sharing (Phase 5).
     |
     | Granting and re-keying are administrator abilities rather than write
     | abilities: an editor may change what is in the vault, but handing a copy
     | of the Vault Key to somebody new is a power of a different kind, because
     | it cannot be taken back — see the note on rotation in
     | docs/03-cryptographic-design.md#revocation-and-rotation.
     */
    Route::post('/vaults/{vault}/memberships', [VaultMembershipController::class, 'store'])
        ->middleware('can:share,vault')
        ->name('memberships.store');

    /*
     | Handing the vault over (Phase 5, task 9). Its own ability rather than a
     | reuse of `share`, because it is the one grant that cannot be taken back by
     | the person making it: the recipient can revoke them afterwards.
     |
     | PATCH on a singular sub-resource rather than a POST, because exactly one
     | owner exists at a time and this replaces them — there is no collection of
     | owners to add to.
     */
    Route::patch('/vaults/{vault}/owner', [VaultOwnershipController::class, 'update'])
        ->middleware('can:transfer,vault')
        ->name('vaults.owner.update');

    /*
     | Moving a vault's payloads onto the current envelope version (Phase 10).
     |
     | A write ability rather than an administrator one, and the distinction is
     | real: this changes no key anybody holds and no plaintext, it re-seals what
     | is already there. Anyone who may edit a secret may re-seal it, because
     | editing it would have done the same thing by a longer route.
     */
    Route::middleware('can:update,vault')->group(function (): void {
        Route::get('/vaults/{vault}/reseal', [VaultResealController::class, 'create'])
            ->name('vaults.reseal');
        Route::post('/vaults/{vault}/reseal', [VaultResealController::class, 'store'])
            ->name('vaults.reseal.store');
    });

    Route::middleware('can:rekey,vault')->group(function (): void {
        Route::get('/vaults/{vault}/rekey', [VaultRekeyController::class, 'create'])
            ->name('vaults.rekey');
        Route::post('/vaults/{vault}/rekey', [VaultRekeyController::class, 'store'])
            ->name('vaults.rekey.store');

        /*
         | How often this vault asks to be reminded its key is old (Phase 10).
         | A reminder and not a schedule: rotation needs a member's browser, so
         | there is no job this could ever trigger.
         */
        Route::patch('/vaults/{vault}/rekey/schedule', [VaultRekeyController::class, 'schedule'])
            ->name('vaults.rekey.schedule');
    });

    /*
     | Accepting is the recipient's, revoking is an administrator's, and the two
     | are different abilities on the same row rather than one "manage
     | membership" permission — only the recipient can have compared the
     | granter's fingerprint.
     */
    Route::patch('/memberships/{membership}', [VaultMembershipController::class, 'accept'])
        ->middleware('can:accept,membership')
        ->name('memberships.accept');

    Route::delete('/memberships/{membership}', [VaultMembershipController::class, 'revoke'])
        ->middleware('can:revoke,membership')
        ->name('memberships.revoke');

    /*
     | The directory lookup that sharing starts from. Rate limited because it
     | confirms whether a handle exists — accepted leakage within an invited
     | group (D11), but not something to leave open to a sweep.
     */
    Route::get('/users/{handle}/identity', [UserIdentityController::class, 'show'])
        ->middleware('throttle:30,1')
        ->name('users.identity');

    Route::post('/account/pins', [PinStoreController::class, 'update'])->name('pins.update');

    Route::get('/lockboxes/{lockbox}', [LockboxController::class, 'show'])
        ->middleware('can:view,lockbox')
        ->name('lockboxes.show');

    Route::middleware('can:update,lockbox')->group(function (): void {
        Route::patch('/lockboxes/{lockbox}', [LockboxController::class, 'update'])
            ->name('lockboxes.update');
        Route::post('/lockboxes/{lockbox}/secrets', [SecretController::class, 'store'])
            ->name('secrets.store');
        Route::post('/lockboxes/{lockbox}/files', [FileController::class, 'store'])
            ->name('files.store');
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

    /*
     | Version history (Phase 8).
     |
     | Reading history needs only `view`: a member who can read the current
     | password can read the ones before it, since they hold the Vault Key
     | either way and pretending otherwise would be a permission that enforces
     | nothing.
     |
     | There is no route that *creates* a version. One is written only as the
     | other half of an edit, in the same transaction as the update it
     | supersedes, because a history that can be appended to on its own is a
     | history that can be made to say something that never happened. Restoring
     | goes through `secrets.update` for the same reason — it is an ordinary
     | write carrying an old payload, so it meets the same concurrency guard and
     | archives whatever it replaces.
     |
     | Purging is `update` rather than `delete`: it destroys history without
     | touching the secret, and requiring the ability to delete the secret in
     | order to erase its past would be the wrong shape of permission.
     */
    /*
     | Creating a share link needs `update` on the secret rather than `view`.
     |
     | A viewer can already read the secret and could paste it into an email, so
     | this is not a confidentiality boundary — it is that a share link creates a
     | *durable* server-side artefact with the creator's name on it, and making
     | one of those is a different act from reading.
     */
    Route::post('/secrets/{secret}/links', [ShareLinkController::class, 'store'])
        ->middleware('can:update,secret')
        ->name('links.store');

    Route::delete('/links/{link}', [ShareLinkController::class, 'destroy'])
        ->middleware('can:revoke,link')
        ->name('links.destroy');

    Route::get('/secrets/{secret}/history', [SecretHistoryController::class, 'index'])
        ->middleware('can:view,secret')
        ->name('secrets.history');

    Route::delete('/secrets/{secret}/history', [SecretHistoryController::class, 'destroy'])
        ->middleware('can:update,secret')
        ->name('secrets.history.destroy');

    /*
     | Files (Phase 6). The body is chunked, so a file has two routes where a
     | secret has one — and the chunk routes are authorised in their own right
     | rather than trusting the check that ran when the row was created. An
     | upload is resumable, which means there is a window during which a real,
     | half-finished record is waiting for writes; that is exactly the window in
     | which an unauthorised write would land on somebody else's row.
     |
     | `whereNumber` on the index keeps a path segment from ever reaching the
     | controller as anything but an integer, so the bounds check has an integer
     | to check.
     */
    Route::get('/files/{file}/status', [FileController::class, 'status'])
        ->middleware('can:view,file')
        ->name('files.status');

    Route::get('/files/{file}/chunks/{index}', [FileChunkController::class, 'show'])
        ->middleware('can:view,file')
        ->whereNumber('index')
        ->name('files.chunks.show');

    Route::put('/files/{file}/chunks/{index}', [FileChunkController::class, 'store'])
        ->middleware('can:update,file')
        ->whereNumber('index')
        ->name('files.chunks.store');

    Route::delete('/files/{file}', [FileController::class, 'destroy'])
        ->middleware('can:delete,file')
        ->name('files.destroy');

    Route::post('/account/password', [RecoveryController::class, 'update'])->name('password.update');

    /*
     | Re-stretching the same password at raised parameters (Phase 10). Silent,
     | on the next login, because that is the only moment a browser holds the
     | password — and it demands the current auth key anyway, since a re-wrap
     | the server cannot inspect is otherwise indistinguishable from an attacker
     | changing the password to one they chose.
     */
    Route::post('/account/kdf', KdfUpgradeController::class)->name('kdf.upgrade');

    /*
     | Replacing your own identity keys (Phase 10). Self-service, because you
     | still hold the old private key and can therefore re-seal every Vault Key
     | sealed to it yourself — no vault owner is involved and no Vault Key
     | changes. All or nothing: the old key is discarded when this lands, so a
     | membership left out could never be opened again.
     */
    Route::get('/account/identity', [IdentityRotationController::class, 'create'])
        ->name('identity.rotate');
    Route::post('/account/identity', [IdentityRotationController::class, 'store'])
        ->name('identity.rotate.store');
    Route::post('/account/recovery-kit', [RecoveryController::class, 'reissue'])
        ->name('recovery-kit.reissue');

    Route::get('/account/two-factor', [TotpController::class, 'create'])->name('totp.create');
    Route::post('/account/two-factor', [TotpController::class, 'store'])->name('totp.store');
    Route::delete('/account/two-factor', [TotpController::class, 'destroy'])->name('totp.destroy');
});
