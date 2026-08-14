<?php

use App\Models\Invite;
use App\Models\User;
use App\Models\UserKeyWrap;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Inertia\Testing\AssertableInertia as Assert;

/**
 * Registration is invite-only, and everything of value in the payload was
 * produced in the browser. These tests check that the server stores what it is
 * given, verifies the invitation, and never gains anything it could decrypt
 * with.
 */
/**
 * @param  array<string, mixed>  $overrides
 * @return array<string, mixed>
 */
function registrationPayload(array $overrides = []): array
{
    return array_merge([
        'uuid' => (string) Str::uuid7(),
        'display_name' => 'Ada Lovelace',
        'handle' => 'ada',
        'kdf_salt' => base64_encode(random_bytes(16)),
        'kdf_params' => ['m' => 65536, 't' => 3, 'p' => 1],
        'auth_key' => base64_encode(random_bytes(32)),
        'wrapped_user_key' => base64_encode(random_bytes(74)),
        'recovery_salt' => base64_encode(random_bytes(16)),
        'recovery_wrapped_user_key' => base64_encode(random_bytes(74)),
        'recovery_auth_key' => base64_encode(random_bytes(32)),
        'x25519_public_key' => base64_encode(random_bytes(32)),
        'ed25519_public_key' => base64_encode(random_bytes(32)),
        'x25519_private_key_ct' => base64_encode(random_bytes(74)),
        'ed25519_private_key_ct' => base64_encode(random_bytes(74)),
        'self_signature' => base64_encode(random_bytes(64)),
        'fingerprint' => base64_encode(random_bytes(32)),
    ], $overrides);
}

function usableInvite(string $token = 'a-valid-invitation-token'): Invite
{
    return Invite::factory()->withToken($token)->create(['email' => 'ada@example.com']);
}

describe('the invitation', function () {
    it('shows the form for a usable invitation', function () {
        usableInvite();

        $this->get('/register/a-valid-invitation-token')
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page->component('auth/Register')->where('email', 'ada@example.com'));
    });

    /*
     | 404 rather than 403 throughout: there is no reason to confirm that a
     | token ever existed.
     */
    it('rejects an unknown token', function () {
        $this->get('/register/not-a-real-token')->assertNotFound();
    });

    it('rejects an expired invitation', function () {
        Invite::factory()->withToken('expired-token')->expired()->create();

        $this->get('/register/expired-token')->assertNotFound();
        $this->postJson('/register/expired-token', registrationPayload())->assertNotFound();
    });

    it('rejects an invitation that was already accepted', function () {
        Invite::factory()->withToken('used-token')->accepted()->create();

        $this->get('/register/used-token')->assertNotFound();
    });

    it('marks the invitation accepted so it cannot be reused', function () {
        $invite = usableInvite();

        $this->postJson('/register/a-valid-invitation-token', registrationPayload())->assertOk();

        expect($invite->refresh()->accepted_at)->not->toBeNull();

        // Registration signs the new account in, and the register route is
        // guest-only — so a reuse attempt has to come from a signed-out session
        // to reach the invitation check at all.
        auth()->logout();

        $this->postJson('/register/a-valid-invitation-token', registrationPayload([
            'handle' => 'second', 'uuid' => (string) Str::uuid7(),
        ]))->assertNotFound();
    });

    it('binds the account to the invited address, not one the client supplies', function () {
        usableInvite();

        $this->postJson('/register/a-valid-invitation-token', registrationPayload([
            'email' => 'attacker@example.com',
        ]))->assertOk();

        expect(User::sole()->email)->toBe('ada@example.com');
    });
});

describe('what the server stores', function () {
    beforeEach(fn () => usableInvite());

    it('creates the account, identity and both key wrappings', function () {
        $payload = registrationPayload();

        $this->postJson('/register/a-valid-invitation-token', $payload)->assertOk();

        $user = User::sole();

        expect($user->uuid)->toBe($payload['uuid'])
            ->and($user->handle)->toBe('ada')
            ->and($user->kdf_params)->toBe(['m' => 65536, 't' => 3, 'p' => 1])
            ->and($user->identity)->not->toBeNull()
            ->and($user->keyWraps)->toHaveCount(2);

        $methods = $user->keyWraps->pluck('method')->sort()->values()->all();

        expect($methods)->toBe([UserKeyWrap::METHOD_PASSWORD, UserKeyWrap::METHOD_RECOVERY]);
    });

    /*
     | The whole point. The auth key proves the client knew the password; it is
     | stored only as a slow hash and is useless for decryption either way.
     */
    it('stores the auth key only as a hash', function () {
        $payload = registrationPayload();

        $this->postJson('/register/a-valid-invitation-token', $payload)->assertOk();

        $user = User::sole();

        expect($user->auth_key_hash)->not->toBe(payloadString($payload, 'auth_key'))
            ->and($user->auth_key_hash)->toStartWith('$argon2id$')
            ->and(Hash::check(payloadString($payload, 'auth_key'), $user->auth_key_hash))->toBeTrue();
    });

    it('stores the recovery verifier only as a hash', function () {
        $payload = registrationPayload();

        $this->postJson('/register/a-valid-invitation-token', $payload)->assertOk();

        $wrap = User::sole()->keyWraps()->where('method', UserKeyWrap::METHOD_RECOVERY)->sole();

        expect($wrap->verifier_hash)->not->toBe(payloadString($payload, 'recovery_auth_key'))
            ->and(Hash::check(payloadString($payload, 'recovery_auth_key'), (string) $wrap->verifier_hash))->toBeTrue();
    });

    it('signs the new account in', function () {
        $this->postJson('/register/a-valid-invitation-token', registrationPayload())->assertOk();

        $this->assertAuthenticatedAs(User::sole());
    });
});

describe('validation', function () {
    beforeEach(fn () => usableInvite());

    it('rejects a payload missing any required field', function (string $field) {
        $payload = registrationPayload();
        unset($payload[$field]);

        $this->postJson('/register/a-valid-invitation-token', $payload)
            ->assertStatus(422)
            ->assertJsonValidationErrors($field);
    })->with([
        'uuid', 'display_name', 'handle', 'kdf_salt', 'auth_key', 'wrapped_user_key',
        'recovery_salt', 'recovery_wrapped_user_key', 'recovery_auth_key',
        'x25519_public_key', 'ed25519_public_key', 'self_signature', 'fingerprint',
    ]);

    /*
     | The server checks the *shape* of key material and nothing else. A 31-byte
     | public key is not a public key, and accepting one would store something
     | no client could ever use.
     */
    it('rejects key material of the wrong length', function (string $field, int $bytes) {
        $this->postJson('/register/a-valid-invitation-token', registrationPayload([
            $field => base64_encode(random_bytes(max(1, $bytes))),
        ]))->assertStatus(422)->assertJsonValidationErrors($field);
    })->with([
        ['auth_key', 31],
        ['auth_key', 33],
        ['kdf_salt', 15],
        ['x25519_public_key', 16],
        ['ed25519_public_key', 64],
        ['self_signature', 32],
        ['fingerprint', 16],
    ]);

    it('rejects material that is not base64', function () {
        $this->postJson('/register/a-valid-invitation-token', registrationPayload([
            'auth_key' => 'definitely!not!base64!',
        ]))->assertStatus(422)->assertJsonValidationErrors('auth_key');
    });

    it('rejects a v4 uuid, since the AAD binding assumes v7', function () {
        $this->postJson('/register/a-valid-invitation-token', registrationPayload([
            'uuid' => (string) Str::uuid(),
        ]))->assertStatus(422)->assertJsonValidationErrors('uuid');
    });

    it('rejects KDF parameters below the floor', function () {
        $this->postJson('/register/a-valid-invitation-token', registrationPayload([
            'kdf_params' => ['m' => 8, 't' => 1, 'p' => 1],
        ]))->assertStatus(422);
    });

    it('rejects a duplicate handle', function () {
        User::factory()->create(['handle' => 'ada']);

        $this->postJson('/register/a-valid-invitation-token', registrationPayload())
            ->assertStatus(422)
            ->assertJsonValidationErrors('handle');
    });

    it('rejects a handle with unusable characters', function (string $handle) {
        $this->postJson('/register/a-valid-invitation-token', registrationPayload(['handle' => $handle]))
            ->assertStatus(422)
            ->assertJsonValidationErrors('handle');
    })->with(['has space', 'Ünicode', '-leading-dash', 'sym@bol', '']);

    it('leaves no partial account behind when validation fails', function () {
        $this->postJson('/register/a-valid-invitation-token', registrationPayload(['auth_key' => 'nope']))
            ->assertStatus(422);

        expect(User::count())->toBe(0);
    });
});
