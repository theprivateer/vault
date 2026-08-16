<?php

namespace App\Providers;

use App\Models\User;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Facades\URL;
use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        //
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        $this->configureModels();
        $this->configureProductionSafety();
        $this->configureRateLimiting();
    }

    /**
     * The KDF-params endpoint has to answer before authentication, so it is
     * limited by IP alone. Login is limited per IP *and* per account inside the
     * controller, where the account is known.
     *
     * The two broad limiters below are the Phase 11 review: every route in the
     * application carries one, not just the credential endpoints. What they are
     * for is different from what the login limiter is for — nobody guesses a
     * vault UUID 5,000 times a minute and gets in — so they are set where they
     * bound damage without being felt. A stolen session is the case they exist
     * for: it can read what its owner could read, and this decides whether that
     * takes a minute or a week. `tests/Feature/RateLimitTest.php` fails if a new
     * route escapes both.
     */
    private function configureRateLimiting(): void
    {
        RateLimiter::for('kdf-params', fn (Request $request) => Limit::perMinute(
            Config::integer('vault.throttle.kdf_params_per_minute')
        )->by($request->ip()));

        /*
         | Deliberately generous, because a file upload is many requests: a
         | hundred-megabyte attachment is a hundred chunk PUTs, and a limit that
         | made a legitimate upload fail halfway would be a limit somebody turns
         | off.
         |
         | Per account *and* per address, for the same reason the login limiter
         | is both: one bounds what a single stolen session can drain, the other
         | bounds a host working through several.
         */
        RateLimiter::for('authenticated', function (Request $request): array {
            $user = $request->user();
            $account = $user instanceof User ? $user->uuid : (string) $request->ip();

            return [
                Limit::perMinute(Config::integer('vault.throttle.authenticated_per_minute'))
                    ->by('account:'.$account),
                Limit::perMinute(Config::integer('vault.throttle.address_per_minute'))
                    ->by('address:'.$request->ip()),
            ];
        });

        /*
         | Everything reachable without a session. Lower, because there is
         | nothing here a person does in bulk — sign in, recover, open an
         | invitation — and because these are the pages an unauthenticated
         | stranger can reach at all.
         */
        RateLimiter::for('guest', fn (Request $request) => Limit::perMinute(
            Config::integer('vault.throttle.guest_per_minute')
        )->by($request->ip()));
    }

    /**
     * Strict mode turns silent data bugs into loud ones.
     *
     * `preventSilentlyDiscardingAttributes` matters here beyond the usual
     * convenience: a mass-assignment mistake that quietly drops a ciphertext or
     * a wrapped key would otherwise look like a successful write.
     */
    private function configureModels(): void
    {
        Model::shouldBeStrict();
        Model::unguard(false);
    }

    private function configureProductionSafety(): void
    {
        if (! $this->app->isProduction()) {
            return;
        }

        // The client-side crypto is meaningless if the bundle delivering it can
        // be served or downgraded over plaintext.
        URL::forceScheme('https');

        DB::prohibitDestructiveCommands();
    }
}
