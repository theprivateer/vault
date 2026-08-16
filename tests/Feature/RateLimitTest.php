<?php

/**
 * Phase 11, task 4: rate limiting across every endpoint, not just the
 * credential ones.
 *
 * The interesting assertion is the sweep. Individual limits are easy to add and
 * easy to forget, and the route that gets forgotten is always the new one — so
 * this walks the whole routing table and fails on anything that carries no
 * limiter at all. A new endpoint either falls inside a group that throttles it
 * or it names its own; there is no third option that passes.
 *
 * Guards SR6 in docs/02-threat-model.md, and the reasoning about what these
 * broader limits are actually for is in config/vault.php.
 */

use App\Models\User;
use App\Models\UserKeyWrap;
use Illuminate\Support\Facades\Route;

/**
 * Routes that deliberately carry no limiter.
 *
 * Short and staying short. Each entry is a decision, not an oversight.
 */
const UNTHROTTLED = [
    // The health check. Monitoring polls it on a schedule and a throttled
    // health endpoint reports an outage it caused itself.
    'up',
    // A redirect to /vaults that touches nothing and reads nothing.
    'home',
];

/*
 | This is the assertion that found `storage.local` and `storage.local.upload`:
 | two routes nobody in this repository wrote, registered by a framework default
 | on the disk that holds every file ciphertext, reading and writing outside the
 | vault policies and outside the audit log. They are gone now — see the note in
 | config/filesystems.php — but the reason to keep sweeping is that neither of
 | them would ever have appeared in a review of this application's own code.
 */
it('rate limits every route it serves', function () {
    $unlimited = collect(Route::getRoutes()->getRoutes())
        ->reject(fn ($route): bool => in_array($route->getName() ?? $route->uri(), UNTHROTTLED, true))
        ->reject(fn ($route): bool => collect($route->gatherMiddleware())
            ->contains(fn ($middleware): bool => is_string($middleware)
                && str_starts_with($middleware, 'throttle:')))
        ->map(fn ($route): string => $route->getName() ?? $route->uri());

    expect($unlimited->all())->toBe([]);
});

/** An account that can sign in and reach /vaults. */
function throttledAccount(): User
{
    $user = User::factory()->create();

    UserKeyWrap::factory()->for($user)->create();

    return $user;
}

/*
 | Confirms the broad limiter actually bites, rather than being registered and
 | never consulted. Driven through real requests rather than by calling the
 | limiter, because the wiring is the part that goes wrong.
 */
it('answers 429 once an account exceeds its allowance', function () {
    config()->set('vault.throttle.authenticated_per_minute', 3);

    $this->actingAs(throttledAccount());

    foreach (range(1, 3) as $attempt) {
        $this->get('/vaults')->assertOk();
    }

    $this->get('/vaults')->assertStatus(429);
});

/*
 | Two limits and not one, and this is what the second is for: per account
 | alone, a host holding several stolen sessions gets the whole allowance again
 | with each of them.
 */
it('holds several accounts on one address to a shared ceiling', function () {
    config()->set('vault.throttle.authenticated_per_minute', 100);
    config()->set('vault.throttle.address_per_minute', 3);

    $this->actingAs(throttledAccount());

    foreach (range(1, 3) as $attempt) {
        $this->get('/vaults')->assertOk();
    }

    // A different account, nowhere near its own allowance, from the same host.
    $this->actingAs(throttledAccount())->get('/vaults')->assertStatus(429);
});

/*
 | And the converse, which is what the *first* limit is for: one account being
 | ground down must not lock out everybody else behind the same NAT.
 */
it('does not spend one account allowance on another', function () {
    config()->set('vault.throttle.authenticated_per_minute', 3);
    config()->set('vault.throttle.address_per_minute', 100);

    $this->actingAs(throttledAccount());

    foreach (range(1, 4) as $attempt) {
        $this->get('/vaults');
    }

    $this->actingAs(throttledAccount())->get('/vaults')->assertOk();
});

it('applies a tighter limit to unauthenticated pages than to sessions', function () {
    expect(config()->integer('vault.throttle.guest_per_minute'))
        ->toBeLessThan(config()->integer('vault.throttle.authenticated_per_minute'));
});
