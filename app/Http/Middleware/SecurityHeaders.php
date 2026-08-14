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
        // Phase 1 runs all key material inside a Web Worker. Vite emits workers
        // as real files under the build directory, so 'self' is sufficient and
        // blob: is deliberately not allowed.
        'worker-src' => "'self'",
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
        }

        // TODO(Phase 11): add `require-trusted-types-for 'script'` and a Trusted
        // Types policy once the surface that needs auditing exists.

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
