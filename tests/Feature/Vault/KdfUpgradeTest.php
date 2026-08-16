<?php

use App\Enums\AuditAction;
use App\Models\AuditEvent;
use App\Models\User;
use App\Models\UserKeyWrap;
use Database\Factories\EnvelopeFixtures;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Hash;

/**
 * Silent KDF upgrades, and the takeover they would be without one check.
 *
 * The mechanics are a password change that keeps the password, so most of what
 * matters here is what the endpoint refuses. Two things in particular:
 *
 *  - **Without proof of the current password this is account takeover.** The
 *    wrapping is opaque to the server, so a re-wrap under a password an attacker
 *    chose looks exactly like a genuine upgrade. Only `current_auth_key` tells
 *    them apart.
 *  - **An upgrade endpoint that accepts a downgrade is a downgrade endpoint.**
 *    The client picks the parameters and derives at them; nothing else in the
 *    system would notice an account quietly moved to 8 MiB and one pass.
 */

/**
 * The current auth key, base64 encoded.
 *
 * Base64 rather than raw bytes because that is what `auth_key_hash` is a hash
 * of: the client posts the encoded form and the server hashes the string it
 * received, never decoding it. Hashing the bytes here instead would produce a
 * test that fails for a reason unrelated to anything it is checking.
 */
function authKey(): string
{
    return base64_encode(str_repeat('k', 32));
}

/** An account whose stretching is behind whatever the deployment now wants. */
function staleUser(): User
{
    $user = User::factory()->create([
        'kdf_params' => ['m' => 16384, 't' => 2, 'p' => 1],
        'auth_key_hash' => Hash::make(authKey()),
    ]);

    $user->keyWraps()->create([
        'method' => UserKeyWrap::METHOD_PASSWORD,
        'wrapped_user_key' => EnvelopeFixtures::envelope(48),
        'salt' => base64_encode(random_bytes(16)),
    ]);

    return $user;
}

/**
 * @param  array<string, mixed>  $overrides
 * @return array<string, mixed>
 */
function upgradePayload(array $overrides = []): array
{
    return [
        'current_auth_key' => authKey(),
        'kdf_salt' => base64_encode(random_bytes(16)),
        'kdf_params' => ['m' => 65536, 't' => 3, 'p' => 1],
        'auth_key' => base64_encode(random_bytes(32)),
        'wrapped_user_key' => EnvelopeFixtures::envelope(48),
        ...$overrides,
    ];
}

beforeEach(function () {
    Config::set('vault.kdf', ['m' => 65536, 't' => 3, 'p' => 1]);
});

describe('being told an upgrade is due', function () {
    it('names the new parameters in the login response', function () {
        $user = staleUser();

        $this->postJson('/login', [
            'email' => $user->email,
            'auth_key' => authKey(),
        ])
            ->assertOk()
            ->assertJsonPath('kdfUpgrade', ['m' => 65536, 't' => 3, 'p' => 1]);
    });

    it('says nothing to an account already at the target', function () {
        $user = staleUser();
        $user->forceFill(['kdf_params' => ['m' => 65536, 't' => 3, 'p' => 1]])->save();

        $this->postJson('/login', [
            'email' => $user->email,
            'auth_key' => authKey(),
        ])
            ->assertOk()
            ->assertJsonPath('kdfUpgrade', null);
    });

    /*
     | The answer is `max` per parameter, not the target wholesale. An account
     | deliberately raised above the default on one number must not be pulled
     | back down to it by an operation called "upgrade".
     */
    it('keeps a parameter the account had already raised', function () {
        $user = staleUser();
        $user->forceFill(['kdf_params' => ['m' => 131072, 't' => 2, 'p' => 1]])->save();

        $this->postJson('/login', [
            'email' => $user->email,
            'auth_key' => authKey(),
        ])
            ->assertOk()
            ->assertJsonPath('kdfUpgrade', ['m' => 131072, 't' => 3, 'p' => 1]);
    });
});

describe('applying the upgrade', function () {
    it('writes the new salt, parameters, auth key and wrapping', function () {
        $user = staleUser();
        $salt = base64_encode(random_bytes(16));
        $newAuthKey = base64_encode(random_bytes(32));
        $wrapping = EnvelopeFixtures::envelope(48);

        $payload = upgradePayload([
            'kdf_salt' => $salt,
            'auth_key' => $newAuthKey,
            'wrapped_user_key' => $wrapping,
        ]);

        $this->actingAs($user)->postJson('/account/kdf', $payload)->assertOk();

        $user->refresh();

        expect($user->kdf_params)->toBe(['m' => 65536, 't' => 3, 'p' => 1])
            ->and($user->kdf_salt)->toBe($salt)
            ->and(Hash::check($newAuthKey, $user->auth_key_hash))->toBeTrue()
            ->and(
                (string) $user->keyWraps()
                    ->where('method', UserKeyWrap::METHOD_PASSWORD)
                    ->sole()->wrapped_user_key
            )->toBe($wrapping);
    });

    /*
     | The whole reason the User Key indirection exists. Every vault key,
     | identity key and payload is wrapped under the User Key, and the User Key
     | itself does not change — only its wrapping does — so an upgrade re-encrypts
     | precisely nothing.
     */
    it('leaves the recovery wrapping alone', function () {
        $user = staleUser();

        $recovery = $user->keyWraps()->create([
            'method' => UserKeyWrap::METHOD_RECOVERY,
            'wrapped_user_key' => EnvelopeFixtures::envelope(48),
            'salt' => base64_encode(random_bytes(16)),
            'verifier_hash' => Hash::make('recovery'),
        ]);

        $before = $recovery->wrapped_user_key->base64;

        $this->actingAs($user)->postJson('/account/kdf', upgradePayload())->assertOk();

        expect($recovery->refresh()->wrapped_user_key->base64)->toBe($before);
    });

    it('records what the account moved to', function () {
        $user = staleUser();

        $this->actingAs($user)->postJson('/account/kdf', upgradePayload())->assertOk();

        $event = AuditEvent::query()->where('action', AuditAction::KdfUpgraded)->sole();

        expect($event->actor_uuid)->toBe($user->uuid)
            ->and($event->metadata)->toBe('{"kdf_m":65536,"kdf_p":1,"kdf_t":3}');
    });
});

describe('what it refuses', function () {
    /*
     | Without this check the endpoint is an account takeover from a session
     | alone: injected script asks the Worker to re-wrap the User Key under a
     | password it chose, posts the result, and the account's password is now
     | one the attacker knows. The server cannot tell that request from a real
     | upgrade by inspecting it — the wrapping is opaque — so the credential is
     | the only thing separating them.
     */
    it('refuses without proof of the current password, and changes nothing', function () {
        $user = staleUser();
        $before = $user->kdf_params;

        $this->actingAs($user)
            ->postJson('/account/kdf', upgradePayload(['current_auth_key' => base64_encode(str_repeat('x', 32))]))
            ->assertStatus(422)
            ->assertJsonValidationErrors('current_auth_key');

        expect($user->refresh()->kdf_params)->toBe($before);
    });

    it('refuses parameters weaker than the account already uses', function () {
        $user = staleUser();
        $user->forceFill(['kdf_params' => ['m' => 262144, 't' => 4, 'p' => 1]])->save();

        $this->actingAs($user)
            ->postJson('/account/kdf', upgradePayload())
            ->assertStatus(422)
            ->assertJsonValidationErrors('kdf_params');

        expect($user->refresh()->kdf_params)->toBe(['m' => 262144, 't' => 4, 'p' => 1]);
    });

    it('refuses parameters weaker than the deployment requires', function () {
        $user = staleUser();

        $this->actingAs($user)
            ->postJson('/account/kdf', upgradePayload(['kdf_params' => ['m' => 16384, 't' => 2, 'p' => 1]]))
            ->assertStatus(422)
            ->assertJsonValidationErrors('kdf_params');
    });

    /*
     | Memory hardness is the parameter that makes Argon2id expensive on the
     | hardware somebody attacking it would rent, so it cannot be traded away for
     | more passes. Comparing a single cost function over m, t and p would have
     | allowed exactly that swap.
     */
    it('refuses more passes in exchange for less memory', function () {
        $user = staleUser();

        $this->actingAs($user)
            ->postJson('/account/kdf', upgradePayload(['kdf_params' => ['m' => 32768, 't' => 8, 'p' => 1]]))
            ->assertStatus(422)
            ->assertJsonValidationErrors('kdf_params');
    });

    it('is not reachable without a session', function () {
        $this->postJson('/account/kdf', upgradePayload())->assertStatus(401);
    });
});
