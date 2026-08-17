<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Vite;
use Symfony\Component\HttpFoundation\Response;

/**
 * Applies the application's security headers, most importantly a strict,
 * nonce-based Content Security Policy.
 *
 * This is the primary control against the XSS adversary (A7) in
 * docs/02-threat-model.md. It is deliberately in place from the first page
 * render: retrofitting a strict CSP onto an existing frontend is far more
 * expensive than building against one.
 *
 * It does NOT defend against a malicious server serving modified JavaScript
 * (A3). Nothing here can.
 */
class SecurityHeaders
{
    /**
     * Directives shared by every environment.
     *
     * @var array<string, string>
     */
    private const BASE_DIRECTIVES = [
        'default-src' => "'none'",
        'img-src' => "'self' data:",
        'font-src' => "'self'",
        'form-action' => "'self'",
        'frame-ancestors' => "'none'",
        'base-uri' => "'none'",
        'object-src' => "'none'",
        'manifest-src' => "'self'",
        /*
         | All key material lives inside a Web Worker, built to a real file
         | under the build directory — so 'self' is sufficient and blob: is
         | deliberately not allowed.
         |
         | `child-src` is not redundant. WebKit does not implement `worker-src`,
         | and an unrecognised directive is ignored rather than honoured: worker
         | loading then falls back to `child-src`, and failing that to
         | `default-src`, which is 'none' here. Without this line Safari blocks
         | the crypto Worker and the application cannot decrypt anything.
         |
         | It cost a day to find, because curl and the Node test suite both see
         | `worker-src` and are satisfied by it. Only a real WebKit browser
         | exercises the fallback chain.
         */
        'worker-src' => "'self'",
        'child-src' => "'self'",

        /*
         | Trusted Types (Phase 11, task 1).
         |
         | `require-trusted-types-for` turns every DOM sink that parses a string
         | as markup or code — innerHTML, outerHTML, script.text, eval, the
         | Function constructor — from something that silently works into
         | something that throws unless the value came from a named policy. It
         | is the one control here that survives a bug in our own code: the
         | classic XSS chain ends at a sink, and this closes the sink.
         |
         | Two policy names are allowed and no more. Vue's runtime-dom
         | registers `vue` at import time and routes its own two sinks through
         | it. `vault-worker` is ours, and it exists because `new Worker(url)`
         | is a Trusted Types sink too — it is a way to make the browser fetch
         | and run code — so the crypto Worker cannot be constructed from a
         | plain string. That policy accepts exactly one URL and throws on
         | anything else (crypto/worker/client.ts), which is what keeps it an
         | auditable exception rather than a hole.
         |
         | `allow-duplicates` is absent, so a second attempt to create a policy
         | under either name — the standard way injected script buys itself a
         | sink — is refused by the browser.
         |
         | There is deliberately no `default` policy. A default policy is
         | consulted for every sink assignment that did not go through a named
         | one, which is precisely the assignments we want to fail. Adding one
         | that returns its input, which is the usual way to make this directive
         | "work", would leave the header in place and the protection gone.
         |
         | This is what forced the progress bar in resources/js/app.ts to be
         | ours rather than Inertia's — see the note there.
         */
        'require-trusted-types-for' => "'script'",
        'trusted-types' => 'vue vault-worker',
    ];

    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        Vite::useCspNonce();

        $response = $next($request);

        foreach ($this->headers($request) as $header => $value) {
            $response->headers->set($header, $value);
        }

        return $response;
    }

    /**
     * @return array<string, string>
     */
    private function headers(Request $request): array
    {
        $headers = [
            'Content-Security-Policy' => $this->contentSecurityPolicy(),
            'X-Content-Type-Options' => 'nosniff',
            'X-Frame-Options' => 'DENY',
            'Referrer-Policy' => 'no-referrer',
            'Cross-Origin-Opener-Policy' => 'same-origin',
            'Cross-Origin-Resource-Policy' => 'same-origin',
            'Permissions-Policy' => $this->permissionsPolicy(),
        ];

        /*
         | Cross-origin isolation. Every subresource this application loads is
         | its own, so `require-corp` costs nothing and closes the document to
         | anything embedded from elsewhere — including a cross-origin document
         | trying to hold a reference to this one.
         |
         | Omitted while the Vite dev server is running, because that serves
         | modules from another origin without a CORP header and the page would
         | not load at all. That is a development-only relaxation of the same
         | kind as the ones in developmentOverrides().
         */
        if (! $this->runningViteDevServer()) {
            $headers['Cross-Origin-Embedder-Policy'] = 'require-corp';
        }

        // Browsers ignore HSTS over plaintext, and sending it there only invites
        // confusion when testing locally.
        if ($request->secure()) {
            $headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload';
        }

        return $headers;
    }

    private function contentSecurityPolicy(): string
    {
        $nonce = Vite::cspNonce();

        $directives = [
            ...self::BASE_DIRECTIVES,
            // 'strict-dynamic' lets the nonce'd entry point load its own chunks
            // without us enumerating every hashed filename Vite produces.
            'script-src' => "'nonce-{$nonce}' 'strict-dynamic'",
            'style-src' => "'nonce-{$nonce}'",
            'connect-src' => "'self'",
        ];

        if ($this->runningViteDevServer()) {
            $directives = [...$directives, ...$this->developmentOverrides()];

            /*
             | Dropped rather than relaxed, because there is no relaxed value:
             | the Vite client builds its own error overlay out of a string, and
             | with Trusted Types enforced a build error would be replaced by a
             | Trusted Types error about the thing that was trying to tell you
             | about the build error.
             |
             | This is why the assertions in tests/Feature/SecurityHeadersTest
             | matter more here than elsewhere — the directive that ships is one
             | nobody exercises while writing code.
             */
            unset($directives['require-trusted-types-for'], $directives['trusted-types']);
        }

        return collect($directives)
            ->map(fn (string $value, string $directive): string => "{$directive} {$value}")
            ->implode('; ');
    }

    /**
     * Relaxations required by the Vite dev server, which serves modules from a
     * separate origin, opens a websocket for HMR, and injects stylesheets as
     * inline <style> elements without a nonce.
     *
     * Gated on the local environment so it can never reach production.
     *
     * @return array<string, string>
     */
    private function developmentOverrides(): array
    {
        $devServer = 'http://localhost:5173 http://[::1]:5173';
        $websocket = 'ws://localhost:5173 ws://[::1]:5173';

        return [
            'connect-src' => "'self' {$devServer} {$websocket}",
            'style-src' => "'self' 'unsafe-inline' {$devServer}",
            'img-src' => "'self' data: {$devServer}",
        ];
    }

    private function runningViteDevServer(): bool
    {
        return app()->environment('local') && Vite::isRunningHot();
    }

    private function permissionsPolicy(): string
    {
        return collect([
            'accelerometer', 'ambient-light-sensor', 'autoplay', 'battery', 'camera',
            'display-capture', 'document-domain', 'encrypted-media', 'fullscreen',
            'geolocation', 'gyroscope', 'magnetometer', 'microphone', 'midi',
            'payment', 'picture-in-picture', 'publickey-credentials-get',
            'screen-wake-lock', 'serial', 'usb', 'xr-spatial-tracking',
        ])->map(fn (string $feature): string => "{$feature}=()")->implode(', ');
    }
}
