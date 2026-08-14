<?php

use App\Models\User;
use App\Models\UserIdentity;
use App\Models\UserKeyWrap;
use Database\Factories\UserFactory;
use Database\Factories\UserKeyWrapFactory;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Facades\Schema;
use Inertia\Testing\AssertableInertia as Assert;

beforeEach(function () {
    RateLimiter::clear('recover:'.sha1('127.0.0.1'));
});

function recoverableAccount(string $email = 'ada@example.com'): User
{
    $user = User::factory()->create(['email' => $email]);

    UserKeyWrap::factory()->for($user)->create();
    UserKeyWrap::factory()->for($user)->recovery()->create();
    UserIdentity::factory()->for($user)->create();

    return $user;
}

/**
 * @param  array<string, mixed>  $overrides
 * @return array<string, mixed>
 */
function passwordChangePayload(array $overrides = []): array
{
    return array_merge([
        'kdf_salt' => base64_encode(random_bytes(16)),
        'kdf_params' => ['m' => 65536, 't' => 3, 'p' => 1],
        'auth_key' => base64_encode(random_bytes(32)),
        'wrapped_user_key' => base64_encode(random_bytes(74)),
    ], $overrides);
}

describe('recovery salt', function () {
    it('answers identically in shape for known and unknown addresses', function () {
        recoverableAccount();

        $known = $this->postJson('/recover/salt', ['email' => 'ada@example.com'])->assertOk();
        $unknown = $this->postJson('/recover/salt', ['email' => 'nobody@example.com'])->assertOk();

        $known->assertJsonStructure(['recoverySalt']);
        $unknown->assertJsonStructure(['recoverySalt']);

        expect(strlen((string) base64_decode(jsonString($unknown, 'recoverySalt'), true)))->toBe(16);
    });

    it('returns a stable decoy for an unknown address', function () {
        $first = $this->postJson('/recover/salt', ['email' => 'nobody@example.com'])->json();
        $second = $this->postJson('/recover/salt', ['email' => 'nobody@example.com'])->json();

        expect($first)->toBe($second);
    });
});

describe('using the recovery kit', function () {
    /*
     | The recovery code never arrives here. The client derives two keys from
     | it: a KEK that stays in the browser, and this auth key. If the server
     | received the code itself, then combined with the wrapping it already
     | holds it would have the User Key outright.
     */
    it('accepts a valid recovery auth key and returns the wrapping', function () {
        $user = recoverableAccount();
        $wrap = $user->keyWraps()->where('method', UserKeyWrap::METHOD_RECOVERY)->sole();

        $this->postJson('/recover', [
            'email' => 'ada@example.com',
            'recovery_auth_key' => UserKeyWrapFactory::RECOVERY_AUTH_KEY,
        ])
            ->assertOk()
            ->assertJsonPath('wrappedUserKey', $wrap->wrapped_user_key->base64)
            ->assertJsonPath('userKeyAad.subject', $user->uuid);

        $this->assertAuthenticatedAs($user);
    });

    it('fails identically for a wrong key and an unknown address', function () {
        recoverableAccount();

        $wrong = $this->postJson('/recover', [
            'email' => 'ada@example.com',
            'recovery_auth_key' => base64_encode(random_bytes(32)),
        ])->assertStatus(422);

        $unknown = $this->postJson('/recover', [
            'email' => 'nobody@example.com',
            'recovery_auth_key' => UserKeyWrapFactory::RECOVERY_AUTH_KEY,
        ])->assertStatus(422);

        expect($wrong->json('errors'))->toBe($unknown->json('errors'));
        $this->assertGuest();
    });

    /*
     | Without verification, anyone naming an address could overwrite that
     | account's password wrapping and lock the owner out. This is the test that
     | pins that hole shut.
     */
    it('does not hand the wrapping to an unverified caller', function () {
        recoverableAccount();

        $response = $this->postJson('/recover', [
            'email' => 'ada@example.com',
            'recovery_auth_key' => base64_encode(random_bytes(32)),
        ])->assertStatus(422);

        expect($response->getContent())->not->toContain('wrappedUserKey');
    });

    it('throttles repeated attempts', function () {
        recoverableAccount();

        foreach (range(1, 5) as $attempt) {
            $this->postJson('/recover', [
                'email' => 'ada@example.com',
                'recovery_auth_key' => base64_encode(random_bytes(32)),
            ])->assertStatus(422);
        }

        $this->postJson('/recover', [
            'email' => 'ada@example.com',
            'recovery_auth_key' => UserKeyWrapFactory::RECOVERY_AUTH_KEY,
        ])->assertStatus(422)->assertJsonFragment(['recovery_code' => ['Too many attempts. Try again shortly.']]);
    });
});

describe('changing the password', function () {
    /*
     | The property that makes a password change cheap: only the wrapping
     | changes. If identity ciphertexts moved, every vault key would have to be
     | re-sealed too, and a password change would become an expensive,
     | interruptible migration.
     */
    it('leaves the identity ciphertexts byte-identical', function () {
        $user = recoverableAccount();
        $before = $user->identity()->sole()->only([
            'x25519_private_key_ct', 'ed25519_private_key_ct',
            'x25519_public_key', 'ed25519_public_key',
        ]);

        $this->actingAs($user)
            ->postJson('/account/password', passwordChangePayload([
                'current_auth_key' => UserFactory::AUTH_KEY,
            ]))
            ->assertOk();

        expect($user->identity()->sole()->only(array_keys($before)))->toEqual($before);
    });

    it('replaces the password wrapping and the auth key hash', function () {
        $user = recoverableAccount();
        $payload = passwordChangePayload(['current_auth_key' => UserFactory::AUTH_KEY]);

        $this->actingAs($user)->postJson('/account/password', $payload)->assertOk();

        $user->refresh();

        expect($user->kdf_salt)->toBe(payloadString($payload, 'kdf_salt'))
            ->and(Hash::check(payloadString($payload, 'auth_key'), $user->auth_key_hash))->toBeTrue()
            ->and(Hash::check(UserFactory::AUTH_KEY, $user->auth_key_hash))->toBeFalse()
            ->and($user->keyWraps()->where('method', UserKeyWrap::METHOD_PASSWORD)->sole()->wrapped_user_key->base64)
            ->toBe(payloadString($payload, 'wrapped_user_key'));
    });

    it('refuses without the current auth key', function () {
        $user = recoverableAccount();

        $this->actingAs($user)
            ->postJson('/account/password', passwordChangePayload())
            ->assertStatus(422)
            ->assertJsonValidationErrors('current_auth_key');
    });

    it('refuses with the wrong current auth key', function () {
        $user = recoverableAccount();

        $this->actingAs($user)
            ->postJson('/account/password', passwordChangePayload([
                'current_auth_key' => base64_encode(random_bytes(32)),
            ]))
            ->assertStatus(422)
            ->assertJsonValidationErrors('current_auth_key');
    });

    it('requires authentication', function () {
        $this->postJson('/account/password', passwordChangePayload())->assertStatus(401);
    });

    /*
     | Someone recovering has by definition forgotten their password, so the
     | usual proof cannot be demanded. The recovery marker takes its place, and
     | is consumed on first use so it cannot authorise a second change.
     */
    it('allows a change without the old password after recovery', function () {
        recoverableAccount();

        $this->postJson('/recover', [
            'email' => 'ada@example.com',
            'recovery_auth_key' => UserKeyWrapFactory::RECOVERY_AUTH_KEY,
        ])->assertOk();

        $this->postJson('/account/password', passwordChangePayload([
            'recovery_salt' => base64_encode(random_bytes(16)),
            'recovery_wrapped_user_key' => base64_encode(random_bytes(74)),
            'recovery_auth_key' => base64_encode(random_bytes(32)),
        ]))->assertOk();

        expect(User::sole()->recovery_used_at)->not->toBeNull();

        // The marker is spent: a second change now needs the new password.
        $this->postJson('/account/password', passwordChangePayload())
            ->assertStatus(422)
            ->assertJsonValidationErrors('current_auth_key');
    });

    it('issues a working new recovery kit alongside', function () {
        recoverableAccount();

        $this->postJson('/recover', [
            'email' => 'ada@example.com',
            'recovery_auth_key' => UserKeyWrapFactory::RECOVERY_AUTH_KEY,
        ])->assertOk();

        $newAuthKey = base64_encode(random_bytes(32));

        $this->postJson('/account/password', passwordChangePayload([
            'recovery_salt' => base64_encode(random_bytes(16)),
            'recovery_wrapped_user_key' => base64_encode(random_bytes(74)),
            'recovery_auth_key' => $newAuthKey,
        ]))->assertOk();

        $this->post('/logout');

        // The old kit no longer works; the new one does.
        $this->postJson('/recover', [
            'email' => 'ada@example.com',
            'recovery_auth_key' => UserKeyWrapFactory::RECOVERY_AUTH_KEY,
        ])->assertStatus(422);

        RateLimiter::clear('recover:'.sha1('127.0.0.1'));

        $this->postJson('/recover', [
            'email' => 'ada@example.com',
            'recovery_auth_key' => $newAuthKey,
        ])->assertOk();
    });
});

describe('password reset', function () {
    it('explains why there is none rather than offering one', function () {
        $this->get('/forgot-password')
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page->component('auth/NoPasswordReset'));
    });

    it('has no reset token table to leak', function () {
        expect(Schema::hasTable('password_reset_tokens'))->toBeFalse();
    });
});
