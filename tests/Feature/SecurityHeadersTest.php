<?php

/**
 * Guards SR10 in docs/02-threat-model.md: the application must set a strict CSP
 * with no `unsafe-inline` or `unsafe-eval` in `script-src`.
 *
 * These assertions are deliberately blunt. A future change that loosens the CSP
 * for convenience should fail the build rather than pass review.
 */
it('sets a content security policy', function () {
    $response = $this->get('/');

    $response->assertOk();
    $response->assertHeader('Content-Security-Policy');
});

it('does not allow inline or eval script execution', function (string $forbidden) {
    expect(cspDirectives($this->get('/'))['script-src'])->not->toContain($forbidden);
})->with(["'unsafe-inline'", "'unsafe-eval'", "'unsafe-hashes'", 'http:', 'https:', '*']);

it('locks down the directives that make XSS exploitable', function (string $directive, string $expected) {
    $directives = cspDirectives($this->get('/'));

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
]);

it('issues a nonce that matches the one on the rendered script tag', function () {
    $response = $this->get('/');

    expect(cspDirectives($response)['script-src'])
        ->toMatch("/^'nonce-[A-Za-z0-9+\/=]+' 'strict-dynamic'$/");

    // The header is worthless if the bundle it authorises carries a different
    // nonce — this is the assertion that proves the two are wired together.
    expect($response->getContent())->toContain('nonce="'.cspNonce($response).'"');
});

it('sets the remaining security headers', function (string $header, string $expected) {
    $this->get('/')->assertHeader($header, $expected);
})->with([
    ['X-Content-Type-Options', 'nosniff'],
    ['X-Frame-Options', 'DENY'],
    ['Referrer-Policy', 'no-referrer'],
    ['Cross-Origin-Opener-Policy', 'same-origin'],
    ['Cross-Origin-Resource-Policy', 'same-origin'],
]);

it('denies powerful browser features by default', function (string $feature) {
    expect($this->get('/')->headers->get('Permissions-Policy'))->toContain("{$feature}=()");
})->with(['camera', 'microphone', 'geolocation', 'usb', 'payment', 'serial']);

it('sends HSTS only over https', function () {
    $this->get('/')->assertHeaderMissing('Strict-Transport-Security');

    $this->get('https://localhost/')
        ->assertHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
});
