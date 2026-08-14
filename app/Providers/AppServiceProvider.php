<?php

namespace App\Providers;

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
     */
    private function configureRateLimiting(): void
    {
        RateLimiter::for('kdf-params', fn (Request $request) => Limit::perMinute(
            Config::integer('vault.throttle.kdf_params_per_minute')
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
