<?php

use App\Http\Middleware\HandleInertiaRequests;
use App\Http\Middleware\SecurityHeaders;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Http\Request;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware $middleware): void {
        // SecurityHeaders is prepended so the CSP nonce exists before anything
        // renders a script or style tag.
        $middleware->web(prepend: [
            SecurityHeaders::class,
        ], append: [
            HandleInertiaRequests::class,
        ]);

        /*
         | Only `APP_URL` and its subdomains may name this application (Phase 11,
         | task 8). Without this, `Host:` is attacker-controlled input that
         | reaches `route()` — so the absolute URL the login response tells the
         | browser to navigate to is built from a header the request supplied.
         |
         | The exploit path is narrow, since a victim's own browser sends the
         | real host, and it widens the moment anything caches a response or
         | puts a generated link in an email. Cheap enough that narrow is not a
         | reason to leave it.
         |
         | Off in local and under tests, which is Laravel's behaviour and the
         | right one: `php artisan serve`, Herd and the test client all use hosts
         | that will not match a production APP_URL.
         */
        $middleware->trustHosts();
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        $exceptions->shouldRenderJsonWhen(
            fn (Request $request) => $request->is('api/*') || $request->expectsJson(),
        );

        /*
         | Flashed input survives a redirect in the session, and exception
         | reports carry it off the box entirely. Nothing here may ever be
         | written down. Entries are listed ahead of the fields existing
         | (Phase 2 adds them) precisely because this is the kind of guardrail
         | that gets remembered only after it was needed. See SR1.
         */
        $exceptions->dontFlash([
            'auth_key',
            'current_password',
            'master_password',
            'password',
            'password_confirmation',
            'recovery_code',
            'wrapped_user_key',
        ]);
    })->create();
