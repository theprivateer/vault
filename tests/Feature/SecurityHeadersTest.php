<?php

/**
 * Exercised against /login because it renders a real Inertia page with the Vite
 * bundle — the nonce assertion needs actual script tags, not a redirect.
 *
 * Guards SR10 in docs/02-threat-model.md: the application must set a strict CSP
 * with no `unsafe-inline` or `unsafe-eval` in `script-src`.
 *
 * These assertions are deliberately blunt. A future change that loosens the CSP
 * for convenience should fail the build rather than pass review.
 */
it('sets a content security policy', function () {
    $response = $this->get('/login');

    $response->assertOk();
    $response->assertHeader('Content-Security-Policy');
});

it('does not allow inline or eval script execution', function (string $forbidden) {
    expect(cspDirectives($this->get('/login'))['script-src'])->not->toContain($forbidden);
})->with(["'unsafe-inline'", "'unsafe-eval'", "'unsafe-hashes'", 'http:', 'https:', '*']);

it('locks down the directives that make XSS exploitable', function (string $directive, string $expected) {
    $directives = cspDirectives($this->get('/login'));

    expect($directives)->toHaveKey($directive)
        ->and($directives[$directive])->toBe($expected);
})->with([
    ['default-src', "'none'"],
    ['object-src', "'none'"],
    ['base-uri', "'none'"],
    ['frame-ancestors', "'none'"],
    ['form-action', "'self'"],
    // Exfiltration has nowhere to go but back to us.
    ['connect-src', "'self'"],
    // Phase 1 holds key material in a Worker; blob: workers stay disallowed.
    ['worker-src', "'self'"],
    ['child-src', "'self'"],
]);

/**
 * `child-src` is not redundant beside `worker-src`, and removing it breaks
 * Safari completely.
 *
 * WebKit does not implement `worker-src`. An unrecognised directive is ignored,
 * not honoured, so worker loading falls back to `child-src` and then to
 * `default-src` — which is `'none'` here. The result is that the crypto Worker
 * never starts, and since every key lives inside it, the application cannot
 * decrypt anything at all.
 *
 * This is asserted separately from the table above because the reason matters
 * more than the value: a future tidy-up that deletes the "duplicate" directive
 * should fail here and read why.
 */
it('names a worker source that browsers without worker-src will still honour', function () {
    $directives = cspDirectives($this->get('/login'));

    expect($directives)->toHaveKey('child-src')
        ->and($directives['child-src'])->toBe("'self'")
        // The fallback that would otherwise apply, and would block everything.
        ->and($directives['default-src'])->toBe("'none'");
});

it('issues a nonce that matches the one on the rendered script tag', function () {
    $response = $this->get('/login');

    expect(cspDirectives($response)['script-src'])
        ->toMatch("/^'nonce-[A-Za-z0-9+\/=]+' 'strict-dynamic'$/");

    // The header is worthless if the bundle it authorises carries a different
    // nonce — this is the assertion that proves the two are wired together.
    expect($response->getContent())->toContain('nonce="'.cspNonce($response).'"');
});

it('sets the remaining security headers', function (string $header, string $expected) {
    $this->get('/login')->assertHeader($header, $expected);
})->with([
    ['X-Content-Type-Options', 'nosniff'],
    ['X-Frame-Options', 'DENY'],
    ['Referrer-Policy', 'no-referrer'],
    ['Cross-Origin-Opener-Policy', 'same-origin'],
    ['Cross-Origin-Resource-Policy', 'same-origin'],
]);

it('denies powerful browser features by default', function (string $feature) {
    expect($this->get('/login')->headers->get('Permissions-Policy'))->toContain("{$feature}=()");
})->with(['camera', 'microphone', 'geolocation', 'usb', 'payment', 'serial']);

it('sends HSTS only over https', function () {
    $this->get('/login')->assertHeaderMissing('Strict-Transport-Security');

    $this->get('https://localhost/login')
        ->assertHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
});
