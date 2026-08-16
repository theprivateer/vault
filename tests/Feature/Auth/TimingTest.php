<?php

/**
 * Phase 11, task 5: the pre-auth endpoints must not answer "no such account"
 * faster than they answer "wrong credential".
 *
 * Every endpoint reachable before authentication takes an email address and has
 * to do something different depending on whether it belongs to anybody. Getting
 * the *response* identical is the easy half and the existing suites cover it —
 * same status, same shape, a decoy salt of the right length. Getting the
 * *duration* identical is the half that gets forgotten, and it defeats all of
 * the other work: an attacker with a stopwatch does not need to read the body.
 *
 * These assert against a count of password-hash operations rather than a clock.
 * On these endpoints the hash is the entire cost — a quarter of a second of
 * bcrypt against a database read measured in microseconds — so two paths that
 * perform the same number of hashes take the same time, and a count does not
 * turn red because CI was busy. Measured wall-clock figures are recorded in
 * docs/07-penetration-test.md, where a number that drifts is information rather
 * than a broken build.
 *
 * Guards SR6 in docs/02-threat-model.md.
 */

use App\Models\User;
use App\Models\UserIdentity;
use App\Models\UserKeyWrap;
use App\Support\DecoyHash;
use Database\Factories\UserFactory;
use Database\Factories\UserKeyWrapFactory;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\RateLimiter;
use Tests\Support\CountingHasher;

beforeEach(function () {
    RateLimiter::clear('login:ip:'.sha1('127.0.0.1'));
    RateLimiter::clear('recover:'.sha1('127.0.0.1'));

    /*
     | The decoy is generated once and then cached, so the very first request a
     | deployment ever serves against an unknown address pays for a hash that no
     | later one does. Warming it here measures the steady state, which is the
     | state every request after the first is in — and the cold cost is named in
     | docs/07-penetration-test.md rather than pretended away.
     */
    DecoyHash::forVerification();
});

/**
 * Runs a request with a counting hasher installed and reports what it cost.
 *
 * The counter is installed around the request and torn down after it, so that
 * the hashing a factory does while building fixtures is never mistaken for work
 * the endpoint did.
 *
 * @param  callable(): mixed  $request
 * @return array{checks: int, makes: int}
 */
function hashOperations(callable $request): array
{
    $counter = new CountingHasher(app(Hasher::class));

    Hash::swap($counter);

    try {
        $request();
    } finally {
        Hash::clearResolvedInstances();
    }

    return ['checks' => $counter->checks, 'makes' => $counter->makes];
}

describe('login', function () {
    /*
     | The one that was wrong. The missing-account path used to generate its
     | decoy hash on the spot — a Hash::make *and* a Hash::check, two bcrypt
     | rounds where the real path does one — so an address nobody had answered
     | about twice as slowly as a wrong password, consistently and in the
     | direction that identifies it.
     */
    it('costs the same whether or not the address belongs to anybody', function () {
        User::factory()->create(['email' => 'ada@example.com']);

        $known = hashOperations(fn () => $this->postJson('/login', [
            'email' => 'ada@example.com',
            'auth_key' => base64_encode(random_bytes(32)),
        ])->assertStatus(422));

        RateLimiter::clear('login:ip:'.sha1('127.0.0.1'));

        $unknown = hashOperations(fn () => $this->postJson('/login', [
            'email' => 'nobody@example.com',
            'auth_key' => base64_encode(random_bytes(32)),
        ])->assertStatus(422));

        expect($unknown)->toBe($known)
            // And specifically: one verification, no generation, on both.
            ->and($known)->toBe(['checks' => 1, 'makes' => 0]);
    });

    /*
     | The decoy is generated once and held for the life of the process, so the
     | assertion above holds on the second unknown address as well as the first.
     | It is deliberately not regenerated per request: that would put the cost
     | back where it was.
     */
    it('does not regenerate its decoy for every unknown address', function () {
        $first = hashOperations(fn () => $this->postJson('/login', [
            'email' => 'nobody@example.com',
            'auth_key' => base64_encode(random_bytes(32)),
        ])->assertStatus(422));

        RateLimiter::clear('login:ip:'.sha1('127.0.0.1'));

        $second = hashOperations(fn () => $this->postJson('/login', [
            'email' => 'also-nobody@example.com',
            'auth_key' => base64_encode(random_bytes(32)),
        ])->assertStatus(422));

        expect($second)->toBe($first);
    });

    /*
     | A backup code used to be found by a loop that returned on the first
     | match, which made the response time a function of the code's position in
     | the list — each step a full password hash. Now every unused code is
     | checked whichever one matches.
     */
    it('checks every backup code regardless of which one matches', function () {
        $codes = ['aaaa-1111', 'bbbb-2222', 'cccc-3333'];

        /*
         | A separate account per attempt, because redeeming a code marks it
         | used and shrinks the pool the next attempt searches — which would
         | make the two counts differ for a reason that has nothing to do with
         | the property under test.
         */
        $cost = function (string $email, string $code) use ($codes): array {
            $user = User::factory()->withTotp()->create(['email' => $email]);
            UserKeyWrap::factory()->for($user)->create();

            foreach ($codes as $stored) {
                $user->backupCodes()->create(['code_hash' => Hash::make($stored)]);
            }

            $measured = hashOperations(fn () => $this->postJson('/login', [
                'email' => $email,
                'auth_key' => UserFactory::AUTH_KEY,
                'totp_code' => $code,
            ])->assertOk());

            $this->post('/logout');

            return $measured;
        };

        // The first code and the last, so a loop that stopped early shows up as
        // a different count rather than as a different clock reading.
        $first = $cost('ada@example.com', 'aaaa-1111');
        $last = $cost('grace@example.com', 'cccc-3333');

        // The auth key, then all three codes, on both attempts.
        expect($first)->toBe($last)->and($first['checks'])->toBe(4);
    });
});

describe('recovery', function () {
    /*
     | Worse than the login form, because it short-circuited: with no wrapping
     | to check against, the `&&` chain never reached the hash at all, so an
     | unknown address returned in about a millisecond where a real one spent a
     | quarter of a second. A cleaner oracle than the endpoint it sits beside.
     */
    it('costs the same whether or not the address has a recovery kit', function () {
        $user = User::factory()->create(['email' => 'ada@example.com']);
        UserKeyWrap::factory()->for($user)->create();
        UserKeyWrap::factory()->for($user)->recovery()->create();
        UserIdentity::factory()->for($user)->create();

        $known = hashOperations(fn () => $this->postJson('/recover', [
            'email' => 'ada@example.com',
            'recovery_auth_key' => base64_encode(random_bytes(32)),
        ])->assertStatus(422));

        RateLimiter::clear('recover:'.sha1('127.0.0.1'));

        $unknown = hashOperations(fn () => $this->postJson('/recover', [
            'email' => 'nobody@example.com',
            'recovery_auth_key' => base64_encode(random_bytes(32)),
        ])->assertStatus(422));

        expect($unknown)->toBe($known)
            ->and($known)->toBe(['checks' => 1, 'makes' => 0]);
    });

    /*
     | An account that exists but never kept a recovery kit is the third case,
     | and it is the one a two-branch fix tends to miss.
     */
    it('costs the same for an account that has no recovery kit at all', function () {
        $user = User::factory()->create(['email' => 'ada@example.com']);
        UserKeyWrap::factory()->for($user)->create();

        $withoutKit = hashOperations(fn () => $this->postJson('/recover', [
            'email' => 'ada@example.com',
            'recovery_auth_key' => UserKeyWrapFactory::RECOVERY_AUTH_KEY,
        ])->assertStatus(422));

        expect($withoutKit)->toBe(['checks' => 1, 'makes' => 0]);
    });
});

describe('kdf params', function () {
    /*
     | No hashing on either path — the salt lookup is a single indexed read and
     | the decoy is an HMAC, both microseconds. Asserted rather than assumed,
     | because the obvious way to make a decoy "look more real" is to derive it
     | with the same work factor the client will use, which would put a
     | deliberate quarter-second on exactly one of the two branches.
     */
    it('hashes nothing on either path', function () {
        User::factory()->create(['email' => 'ada@example.com']);

        $known = hashOperations(fn () => $this->postJson(
            '/auth/kdf-params', ['email' => 'ada@example.com']
        )->assertOk());

        $unknown = hashOperations(fn () => $this->postJson(
            '/auth/kdf-params', ['email' => 'nobody@example.com']
        )->assertOk());

        expect($known)->toBe(['checks' => 0, 'makes' => 0])->and($unknown)->toBe($known);
    });

    it('hashes nothing on either path of the recovery salt lookup', function () {
        $user = User::factory()->create(['email' => 'ada@example.com']);
        UserKeyWrap::factory()->for($user)->recovery()->create();

        $known = hashOperations(fn () => $this->postJson(
            '/recover/salt', ['email' => 'ada@example.com']
        )->assertOk());

        $unknown = hashOperations(fn () => $this->postJson(
            '/recover/salt', ['email' => 'nobody@example.com']
        )->assertOk());

        expect($known)->toBe(['checks' => 0, 'makes' => 0])->and($unknown)->toBe($known);
    });
});
