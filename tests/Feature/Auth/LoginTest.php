<?php

use App\Models\User;
use App\Models\UserKeyWrap;
use App\Support\Totp;
use Database\Factories\UserFactory;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\RateLimiter;

beforeEach(function () {
    RateLimiter::clear('login:ip:'.sha1('127.0.0.1'));
});

/**
 * @param  array<string, mixed>  $attributes
 */
function accountWithWrap(array $attributes = []): User
{
    $user = User::factory()->create($attributes);

    UserKeyWrap::factory()->for($user)->create();

    return $user;
}

describe('kdf params', function () {
    /*
     | SR6. This endpoint must answer before authentication, which makes it the
     | most obvious enumeration oracle in the application. An unknown address
     | must be indistinguishable from a known one.
     */
    it('answers identically in shape for known and unknown addresses', function () {
        accountWithWrap(['email' => 'ada@example.com']);

        $known = $this->postJson('/auth/kdf-params', ['email' => 'ada@example.com'])->assertOk();
        $unknown = $this->postJson('/auth/kdf-params', ['email' => 'nobody@example.com'])->assertOk();

        $known->assertJsonStructure(['kdfSalt', 'kdfParams']);
        $unknown->assertJsonStructure(['kdfSalt', 'kdfParams']);

        // A decoy salt has to be the right size, or its length gives it away.
        expect(strlen((string) base64_decode(jsonString($unknown, 'kdfSalt'), true)))->toBe(16);
    });

    it('returns a stable decoy, so repeating the question reveals nothing', function () {
        $first = $this->postJson('/auth/kdf-params', ['email' => 'nobody@example.com'])->json();
        $second = $this->postJson('/auth/kdf-params', ['email' => 'nobody@example.com'])->json();

        expect($first)->toBe($second);
    });

    it('returns different decoys for different addresses', function () {
        $a = $this->postJson('/auth/kdf-params', ['email' => 'one@example.com'])->json('kdfSalt');
        $b = $this->postJson('/auth/kdf-params', ['email' => 'two@example.com'])->json('kdfSalt');

        expect($a)->not->toBe($b);
    });

    it('returns the real salt for a real account', function () {
        $user = accountWithWrap(['email' => 'ada@example.com']);

        $this->postJson('/auth/kdf-params', ['email' => 'ada@example.com'])
            ->assertJsonPath('kdfSalt', $user->kdf_salt);
    });

    it('is case insensitive about the address', function () {
        $user = accountWithWrap(['email' => 'ada@example.com']);

        $this->postJson('/auth/kdf-params', ['email' => 'ADA@Example.com  '])
            ->assertJsonPath('kdfSalt', $user->kdf_salt);
    });

    it('requires an email', function () {
        $this->postJson('/auth/kdf-params', [])->assertStatus(422);
    });
});

describe('signing in', function () {
    it('accepts the correct auth key and returns the wrapped user key', function () {
        $user = accountWithWrap(['email' => 'ada@example.com']);
        $wrap = $user->keyWraps()->sole();

        $this->postJson('/login', [
            'email' => 'ada@example.com',
            'auth_key' => UserFactory::AUTH_KEY,
        ])
            ->assertOk()
            ->assertJsonPath('bundle.wrappedUserKey', $wrap->wrapped_user_key->base64)
            ->assertJsonPath('bundle.userKeyAad.subject', $user->uuid)
            ->assertJsonPath('bundle.userKeyAad.context', 'user.userkey');

        $this->assertAuthenticatedAs($user);
    });

    it('records the sign-in time', function () {
        accountWithWrap(['email' => 'ada@example.com']);

        $this->postJson('/login', ['email' => 'ada@example.com', 'auth_key' => UserFactory::AUTH_KEY])
            ->assertOk();

        expect(User::sole()->last_login_at)->not->toBeNull();
    });

    /*
     | One message for every failure. Anything more specific tells an attacker
     | which half of the guess was right.
     */
    it('fails identically for an unknown address and a wrong auth key', function () {
        accountWithWrap(['email' => 'ada@example.com']);

        $wrongKey = $this->postJson('/login', [
            'email' => 'ada@example.com',
            'auth_key' => base64_encode(random_bytes(32)),
        ])->assertStatus(422);

        $unknown = $this->postJson('/login', [
            'email' => 'nobody@example.com',
            'auth_key' => UserFactory::AUTH_KEY,
        ])->assertStatus(422);

        expect($wrongKey->json('errors'))->toBe($unknown->json('errors'));
        $this->assertGuest();
    });

    it('rejects an auth key of the wrong length', function () {
        $this->postJson('/login', [
            'email' => 'ada@example.com',
            'auth_key' => base64_encode(random_bytes(16)),
        ])->assertStatus(422)->assertJsonValidationErrors('auth_key');
    });

    it('never returns anything that could decrypt the vault', function () {
        accountWithWrap(['email' => 'ada@example.com']);

        $body = $this->postJson('/login', [
            'email' => 'ada@example.com',
            'auth_key' => UserFactory::AUTH_KEY,
        ])->assertOk()->getContent();

        // The wrapped key is fine — it is inert without the password. A hash or
        // a raw auth key appearing here would not be.
        expect($body)->not->toContain('auth_key_hash')
            ->and($body)->not->toContain(UserFactory::AUTH_KEY)
            ->and($body)->not->toContain('$argon2id$');
    });

    it('signs out and invalidates the session', function () {
        $user = accountWithWrap();

        $this->actingAs($user)->post('/logout')->assertRedirect('/login');

        $this->assertGuest();
    });
});

describe('throttling', function () {
    /*
     | SR6. Per-IP alone would let a distributed attempt grind one account; per
     | account alone would let one host sweep many. Both are needed.
     */
    it('locks out after repeated failures', function () {
        accountWithWrap(['email' => 'ada@example.com']);

        foreach (range(1, 5) as $attempt) {
            $this->postJson('/login', [
                'email' => 'ada@example.com',
                'auth_key' => base64_encode(random_bytes(32)),
            ])->assertStatus(422);
        }

        // Even the correct key is now refused.
        $this->postJson('/login', ['email' => 'ada@example.com', 'auth_key' => UserFactory::AUTH_KEY])
            ->assertStatus(422)
            ->assertJsonFragment(['email' => ['Too many attempts. Try again in 1 minutes.']]);

        $this->assertGuest();
    });

    it('clears the counters on a successful sign in', function () {
        accountWithWrap(['email' => 'ada@example.com']);

        $this->postJson('/login', [
            'email' => 'ada@example.com',
            'auth_key' => base64_encode(random_bytes(32)),
        ])->assertStatus(422);

        $this->postJson('/login', ['email' => 'ada@example.com', 'auth_key' => UserFactory::AUTH_KEY])
            ->assertOk();

        expect(RateLimiter::attempts('login:ip:'.sha1('127.0.0.1')))->toBe(0);
    });

    it('throttles the kdf params endpoint', function () {
        foreach (range(1, 20) as $attempt) {
            $this->postJson('/auth/kdf-params', ['email' => "user{$attempt}@example.com"])->assertOk();
        }

        $this->postJson('/auth/kdf-params', ['email' => 'one-too-many@example.com'])
            ->assertStatus(429);
    });
});

describe('the second factor', function () {
    it('is required once enrolled', function () {
        $secret = Totp::generateSecret();
        accountWithWrap(['email' => 'ada@example.com'])
            ->forceFill(['totp_secret_ct' => $secret, 'totp_confirmed_at' => now()])
            ->save();

        $this->postJson('/login', ['email' => 'ada@example.com', 'auth_key' => UserFactory::AUTH_KEY])
            ->assertStatus(422);

        $this->assertGuest();

        $this->postJson('/login', [
            'email' => 'ada@example.com',
            'auth_key' => UserFactory::AUTH_KEY,
            'totp_code' => Totp::codeAt($secret, time()),
        ])->assertOk();

        $this->assertAuthenticated();
    });

    it('accepts a backup code once and only once', function () {
        $user = accountWithWrap(['email' => 'ada@example.com']);
        $user->forceFill([
            'totp_secret_ct' => Totp::generateSecret(),
            'totp_confirmed_at' => now(),
        ])->save();

        $user->backupCodes()->create(['code_hash' => Hash::make('abcde-fghij')]);

        $this->postJson('/login', [
            'email' => 'ada@example.com',
            'auth_key' => UserFactory::AUTH_KEY,
            'totp_code' => 'abcde-fghij',
        ])->assertOk();

        expect($user->backupCodes()->whereNotNull('used_at')->count())->toBe(1);

        $this->post('/logout');

        $this->postJson('/login', [
            'email' => 'ada@example.com',
            'auth_key' => UserFactory::AUTH_KEY,
            'totp_code' => 'abcde-fghij',
        ])->assertStatus(422);
    });
});
