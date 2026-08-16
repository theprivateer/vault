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
 * Trusted Types (Phase 11, task 1).
 *
 * These two directives are the ones that survive a bug in our own code: with
 * them set, the sinks an XSS payload has to reach — innerHTML, script.text,
 * eval, the Function constructor — throw rather than execute.
 *
 * Asserted as an exact value rather than a "contains", because the failure mode
 * is a widening. `trusted-types vue default` would keep every one of these
 * assertions true if they were written loosely, and would also switch the
 * protection off: a default policy is consulted for exactly the assignments
 * that are supposed to fail.
 */
it('enforces trusted types with no default policy', function () {
    $directives = cspDirectives($this->get('/login'));

    expect($directives)->toHaveKey('require-trusted-types-for')
        ->and($directives['require-trusted-types-for'])->toBe("'script'")
        // Vue's runtime registers a policy under this name for its own two
        // sinks. Nothing in resources/js registers one at all.
        ->and($directives['trusted-types'])->toBe('vue');
});

it('does not allow a policy to be created twice or by default', function (string $forbidden) {
    expect(cspDirectives($this->get('/login'))['trusted-types'])->not->toContain($forbidden);
})->with(['default', "'allow-duplicates'", '*']);

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

/**
 * Subresource integrity (Phase 11, task 2).
 *
 * Asserted on the rendered page rather than on the manifest, because the
 * manifest having the key and the tag carrying the attribute are two different
 * facts and only the second one reaches a browser.
 */
/**
 * The build manifest, narrowed to the two fields these assertions care about.
 *
 * The narrowing throws rather than skipping, because a chunk with no file or no
 * integrity key is the exact failure being looked for, and a loop that quietly
 * ignored it would report success over an unhashed bundle.
 *
 * @return array<string, array{file: string, integrity: string}>
 */
function builtManifest(): array
{
    $decoded = json_decode((string) file_get_contents(public_path('build/manifest.json')), true);

    $manifest = [];

    foreach (is_array($decoded) ? $decoded : [] as $name => $chunk) {
        $file = is_array($chunk) ? ($chunk['file'] ?? null) : null;
        $integrity = is_array($chunk) ? ($chunk['integrity'] ?? null) : null;

        if (! is_string($file) || ! is_string($integrity)) {
            throw new InvalidArgumentException("Manifest chunk [{$name}] has no file or no integrity hash.");
        }

        $manifest[(string) $name] = ['file' => $file, 'integrity' => $integrity];
    }

    return $manifest;
}

describe('subresource integrity', function () {
    it('puts a hash on every script and stylesheet it renders', function () {
        $content = $this->get('/login')->getContent();

        preg_match_all('/<(script|link)\b[^>]*>/', (string) $content, $matches);

        $tags = collect($matches[0])
            // The Inertia head slot renders a title, which carries no file.
            ->filter(fn (string $tag): bool => str_contains($tag, 'src=') || str_contains($tag, 'href='))
            ->filter(fn (string $tag): bool => str_contains($tag, '/build/'));

        expect($tags)->not->toBeEmpty();

        $tags->each(fn (string $tag) => expect($tag)->toContain('integrity="sha384-'));
    });

    /*
     | The hash has to describe the bytes on disk. A plugin that wrote a
     | plausible-looking constant, or hashed rollup's in-memory output before
     | something else rewrote the file, would satisfy every assertion above and
     | none of the ones a browser makes.
     */
    it('publishes a hash that matches the file it names', function () {
        foreach (builtManifest() as $name => $chunk) {
            $file = public_path('build/'.$chunk['file']);
            $raw = hash_file('sha384', $file, true);

            if ($raw === false) {
                throw new RuntimeException("Manifest chunk [{$name}] names a file that cannot be read.");
            }

            expect($chunk['integrity'])->toBe('sha384-'.base64_encode($raw));
        }
    });

    /*
     | The crypto Worker is the one script that matters most here and the one
     | script that cannot carry an integrity attribute: it is loaded by the
     | Worker constructor, which has no integrity option in any browser. Named
     | rather than left as an unexplained gap in the coverage above.
     */
    it('cannot cover the crypto worker, which is loaded without a tag', function () {
        expect(file_exists(public_path('build/crypto.worker.js')))->toBeTrue()
            ->and((string) file_get_contents(public_path('build/manifest.json')))
            ->not->toContain('crypto.worker.js');
    });
});

it('sets the remaining security headers', function (string $header, string $expected) {
    $this->get('/login')->assertHeader($header, $expected);
})->with([
    ['X-Content-Type-Options', 'nosniff'],
    ['X-Frame-Options', 'DENY'],
    ['Referrer-Policy', 'no-referrer'],
    ['Cross-Origin-Opener-Policy', 'same-origin'],
    ['Cross-Origin-Resource-Policy', 'same-origin'],
    // Every subresource here is our own, so isolation costs nothing.
    ['Cross-Origin-Embedder-Policy', 'require-corp'],
]);

it('denies powerful browser features by default', function (string $feature) {
    expect($this->get('/login')->headers->get('Permissions-Policy'))->toContain("{$feature}=()");
})->with(['camera', 'microphone', 'geolocation', 'usb', 'payment', 'serial']);

it('sends HSTS only over https', function () {
    $this->get('/login')->assertHeaderMissing('Strict-Transport-Security');

    $this->get('https://localhost/login')
        ->assertHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
});
