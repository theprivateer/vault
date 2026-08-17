<?php

use App\Http\Controllers\CryptoWorkerController;
use App\Models\User;

/**
 * The crypto Worker script, and the headers without which it does not load
 * (docs/07 F13).
 *
 * This file exists because the Worker used to be a static asset under `public/`,
 * which meant nginx served it and the application's middleware never saw it. The
 * consequence was not cosmetic: a document sending
 * `Cross-Origin-Embedder-Policy: require-corp` may only create a dedicated
 * worker whose **own response** carries a compatible COEP, so the browser
 * refused to load it and the entire application reported that encryption was
 * unavailable.
 *
 * Nothing in the suite could have caught that, because nothing in the suite
 * requested the file at all — it was not a route. Now it is one, and these are
 * the assertions that make the headers a tested property rather than a
 * deployment detail.
 */
beforeEach(function () {
    // The route serves what the build wrote. A suite that invented its own file
    // would pass against a build step that no longer runs.
    if (! is_file(storage_path(CryptoWorkerController::PATH))) {
        $this->markTestSkipped('Run `npm run build:worker` first.');
    }
});

it('serves the worker script', function () {
    $response = $this->get('/crypto.worker.js');

    $response->assertOk();

    expect($response->headers->get('Content-Type'))->toContain('text/javascript');
});

/*
 | The header the outage was about. A document with COEP require-corp cannot
 | create a dedicated worker whose response lacks a compatible one, so this
 | assertion is the difference between an application that encrypts and one that
 | does not.
 */
it('carries the embedder policy a require-corp document demands of its worker', function () {
    $this->get('/crypto.worker.js')
        ->assertHeader('Cross-Origin-Embedder-Policy', 'require-corp');
});

it('is same-origin only, and not sniffable', function () {
    $this->get('/crypto.worker.js')
        ->assertHeader('Cross-Origin-Resource-Policy', 'same-origin')
        ->assertHeader('X-Content-Type-Options', 'nosniff');
});

/*
 | Revalidated rather than cached hard: a browser holding a stale copy of the one
 | script that touches key material is a worse outcome than a round trip.
 */
it('is revalidated rather than cached indefinitely', function () {
    $cacheControl = $this->get('/crypto.worker.js')->headers->get('Cache-Control') ?? '';

    expect($cacheControl)->toContain('no-cache')
        ->and($cacheControl)->not->toContain('immutable');
});

/*
 | Registration and login both encrypt before anybody is authenticated, so a
 | Worker behind `auth` would make it impossible to create an account at all.
 */
it('is reachable without signing in, and also while signed in', function () {
    $this->get('/crypto.worker.js')->assertOk();

    $this->actingAs(User::factory()->create())->get('/crypto.worker.js')->assertOk();
});

/*
 | The path is the contract between vite.worker.config.ts and the controller. A
 | deployment where those two disagree serves a 404 for the Worker, which the
 | interface reports as "encryption unavailable" — the same symptom as the
 | outage, from a different cause, which is why it is worth naming separately.
 */
it('is built to the path the controller reads', function () {
    expect(CryptoWorkerController::PATH)->toBe('app/private/worker/crypto.worker.js')
        ->and(file_get_contents(storage_path(CryptoWorkerController::PATH)))
        ->toContain('vault');
});

it('is not also served from public/, where it would carry no headers at all', function () {
    // The old location. Leaving a copy there would mean two ways to fetch the
    // Worker, one of them headerless and unmiddlewared.
    expect(is_file(public_path('build/crypto.worker.js')))->toBeFalse();
});
