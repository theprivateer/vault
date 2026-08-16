<?php

use App\Http\Middleware\ForgetFlashedInput;
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
            ForgetFlashedInput::class,
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
         | There is deliberately no `dontFlash()` list here.
         |
         | One lived at this spot from Phase 0 until Phase 11.5, naming seven
         | fields. Three of them — `current_password`, `master_password`,
         | `recovery_code` — were written before the schema existed and by the
         | end named nothing in the application at all, while `payload_ct`,
         | `wrapped_item_key` and `recovery_auth_key` had all arrived without
         | being added. It was guarding a form that was never built.
         |
         | An enumerated list of field names is the wrong shape for this
         | problem: it drifts silently, and a stale one reads exactly like a
         | current one. App\Http\Middleware\ForgetFlashedInput drops the
         | flashed input wholesale instead — nothing to keep in step, and
         | nothing a new field can be forgotten from. See SR1, and
         | docs/07-penetration-test.md F11.
         */
    })->create();
