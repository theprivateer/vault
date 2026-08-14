<?php

namespace App\Providers;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
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
