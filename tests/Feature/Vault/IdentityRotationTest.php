<?php

use App\Enums\AuditAction;
use App\Enums\VaultRole;
use App\Models\AuditEvent;
use App\Models\User;
use App\Models\UserIdentity;
use App\Models\UserIdentityArchive;
use App\Models\Vault;
use App\Models\VaultMembership;
use Database\Factories\EnvelopeFixtures;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Str;
use Inertia\Testing\AssertableInertia;

/**
 * Replacing a user's identity keys, from the server's side.
 *
 * The cryptographic half is tested where real keys exist —
 * `resources/js/crypto/rotation.test.ts` for the certificate and
 * `worker/keyring.test.ts` for the re-sealing. What the server is responsible
 * for is narrower and, in one respect, more dangerous than anything it does
 * elsewhere: **it must refuse an incomplete set.**
 *
 * The old private key is discarded when a rotation lands. A membership missing
 * from the submission is a sealed Vault Key with no surviving key to open it —
 * the vault becomes permanently unreadable for that user, silently, with the
 * request having reported success. That is the same failure a partial vault
 * re-key would cause, arriving from the other end of the key hierarchy, and it
 * gets the same defence.
 */

/** A user with published keys, and optionally some vault memberships. */
function rotatingUser(int $vaults = 0): User
{
    $user = User::factory()->create();
    UserIdentity::factory()->for($user)->create();

    for ($i = 0; $i < $vaults; $i++) {
        Vault::factory()->ownedBy(User::factory()->create())->withMember($user, VaultRole::Editor)->create();
    }

    return $user;
}

/**
 * The membership half of a submission: every live one, re-sealed.
 *
 * @return list<array{uuid: string, wrapped_vault_key: string}>
 */
function rotationMemberships(User $user): array
{
    return array_values($user->vaultMemberships()
        ->whereNull('revoked_at')
        ->get()
        ->map(fn (VaultMembership $membership): array => [
            'uuid' => $membership->uuid,
            'wrapped_vault_key' => EnvelopeFixtures::sealedEnvelope(),
        ])
        ->all());
}

/** The retired fingerprint a certificate has to name, lowercase hex. */
function currentFingerprintHex(User $user): string
{
    return bin2hex((string) $user->identity?->fingerprint->bytes());
}

/**
 * A rotation submission that matches the user's live memberships exactly.
 *
 * @param  array<string, mixed>  $overrides
 * @return array<string, mixed>
 */
function rotationPayload(User $user, array $overrides = []): array
{
    $fingerprint = random_bytes(32);

    return [
        'x25519_public_key' => base64_encode(random_bytes(32)),
        'ed25519_public_key' => base64_encode(random_bytes(32)),
        'x25519_private_key_ct' => EnvelopeFixtures::envelope(48),
        'ed25519_private_key_ct' => EnvelopeFixtures::envelope(48),
        'self_signature' => base64_encode(random_bytes(64)),
        'fingerprint' => base64_encode($fingerprint),
        'rotation_payload' => json_encode([
            'v' => 1,
            'userUuid' => $user->uuid,
            'previousFingerprint' => currentFingerprintHex($user),
            'fingerprint' => bin2hex($fingerprint),
            'rotatedAt' => '2026-08-16T09:00:00Z',
        ], JSON_THROW_ON_ERROR),
        'rotation_signature' => base64_encode(random_bytes(64)),
        'memberships' => rotationMemberships($user),
        ...$overrides,
    ];
}

describe('rotating', function () {
    it('replaces the published keys and archives the old ones', function () {
        $user = rotatingUser();
        $before = $user->identity;
        $payload = rotationPayload($user);

        $this->actingAs($user)->post('/account/identity', $payload)->assertRedirect();

        $after = $user->refresh()->identity;

        expect($after?->x25519_public_key->base64)->toBe($payload['x25519_public_key'])
            ->and($after?->fingerprint->base64)->toBe($payload['fingerprint']);

        $archived = UserIdentityArchive::query()->sole();

        expect($archived->fingerprint->base64)->toBe($before?->fingerprint->base64)
            ->and($archived->ed25519_public_key->base64)->toBe($before?->ed25519_public_key->base64)
            ->and($archived->rotation_payload)->toBe($payload['rotation_payload']);
    });

    /*
     | Public halves only. Keeping the retired private keys would make a
     | rotation a rename: the whole point is that whatever may have escaped
     | stops opening things, and it cannot stop if a copy is still on the server.
     */
    it('archives no private key material', function () {
        $user = rotatingUser();
        $before = $user->identity?->x25519_private_key_ct->base64;

        $this->actingAs($user)->post('/account/identity', rotationPayload($user));

        $columns = UserIdentityArchive::query()->sole()->getAttributes();

        expect(array_keys($columns))->not->toContain('x25519_private_key_ct')
            ->and(json_encode($columns, JSON_THROW_ON_ERROR))->not->toContain((string) $before);
    });

    /*
     | The certificate is stored byte for byte, exactly as `grant_payload` is.
     | A signature verifies over bytes, and a round trip through a JSON codec is
     | free to change the escaping — producing notices no peer can verify, which
     | fail in a way indistinguishable from tampering.
     */
    it('stores the certificate byte for byte', function () {
        $user = rotatingUser();
        $fingerprint = random_bytes(32);

        /*
         | Deliberately not PHP's compact encoding: spaces after the colons, and
         | the fields in an order json_encode would not produce from an array
         | built here. If anything on this path decoded and re-encoded it, both
         | would be gone — and every peer's verification would fail against a
         | signature over the bytes the browser actually signed.
         */
        $verbatim = '{"v": 1, "userUuid": "'.$user->uuid.'", "previousFingerprint": "'
            .currentFingerprintHex($user).'", "fingerprint": "'
            .bin2hex($fingerprint).'", "rotatedAt": "2026-08-16T09:00:00Z"}';

        $this->actingAs($user)
            ->post('/account/identity', rotationPayload($user, [
                'fingerprint' => base64_encode($fingerprint),
                'rotation_payload' => $verbatim,
            ]))
            ->assertRedirect();

        expect(UserIdentityArchive::query()->sole()->rotation_payload)->toBe($verbatim);
    });

    it('re-seals every membership key', function () {
        $user = rotatingUser(vaults: 3);
        $memberships = rotationMemberships($user);

        $before = $user->vaultMemberships()->pluck('wrapped_vault_key', 'uuid');

        $this->actingAs($user)
            ->post('/account/identity', rotationPayload($user, ['memberships' => $memberships]))
            ->assertRedirect();

        foreach ($memberships as $submitted) {
            $membership = VaultMembership::query()->where('uuid', $submitted['uuid'])->sole();

            expect($membership->wrapped_vault_key->base64)->toBe($submitted['wrapped_vault_key'])
                ->and($membership->wrapped_vault_key->base64)->not->toBe($before[$submitted['uuid']]);
        }
    });

    /*
     | Rotating your own keys changes nothing about a vault. It is not a re-key,
     | it removes nobody's access, and it does not advance an epoch — a test
     | rather than a comment because the two operations are easy to conflate and
     | the difference is what somebody needs to understand before choosing one.
     */
    it('leaves every vault key, epoch and role untouched', function () {
        $user = rotatingUser(vaults: 2);
        $vault = Vault::query()->firstOrFail();
        $before = [$vault->key_epoch, $vault->wrapped_item_key->base64, $vault->key_rotated_at];

        $this->actingAs($user)->post('/account/identity', rotationPayload($user))->assertRedirect();

        $vault->refresh();

        expect([$vault->key_epoch, $vault->wrapped_item_key->base64, $vault->key_rotated_at])->toEqual($before)
            ->and($vault->rekey_required_at)->toBeNull();
    });

    /*
     | Acceptance records that this user checked somebody *else's* fingerprint.
     | Changing their own keys says nothing about that check, and clearing it
     | would ask everybody to re-verify people they never stopped trusting.
     */
    it('does not clear acceptances', function () {
        $user = rotatingUser(vaults: 1);
        $membership = $user->vaultMemberships()->sole();
        $membership->forceFill(['accepted_at' => now()])->save();

        $this->actingAs($user)->post('/account/identity', rotationPayload($user))->assertRedirect();

        expect($membership->refresh()->accepted_at)->not->toBeNull();
    });

    it('records how many keys moved', function () {
        $user = rotatingUser(vaults: 2);

        $this->actingAs($user)->post('/account/identity', rotationPayload($user))->assertRedirect();

        $event = AuditEvent::query()->where('action', AuditAction::IdentityRotated)->sole();

        expect($event->actor_uuid)->toBe($user->uuid)
            ->and($event->metadata)->toBe('{"count":2}');
    });
});

describe('the completeness rule', function () {
    /*
     | The defence this whole endpoint turns on. The old private key is gone
     | after this, so a membership left out is a vault its owner could never open
     | again — no error, no warning, nothing to recover from.
     */
    it('refuses a submission missing a membership, and changes nothing', function () {
        $user = rotatingUser(vaults: 3);
        $before = $user->identity?->fingerprint->base64;

        $memberships = rotationMemberships($user);
        array_pop($memberships);

        $this->actingAs($user)
            ->post('/account/identity', rotationPayload($user, ['memberships' => $memberships]))
            ->assertSessionHasErrors('memberships');

        expect($user->refresh()->identity?->fingerprint->base64)->toBe($before)
            ->and(UserIdentityArchive::query()->count())->toBe(0);
    });

    /*
     | Nothing extra either. A submission naming a membership that is not in the
     | live set is a client working from a stale picture, and the entries it did
     | send are then unlikely to be the whole set — the same reasoning as the
     | vault re-key, and the same refusal.
     */
    it('refuses a submission naming a membership that is not theirs', function () {
        $user = rotatingUser(vaults: 1);

        $memberships = rotationMemberships($user);
        $memberships[] = [
            'uuid' => (string) Str::uuid7(),
            'wrapped_vault_key' => EnvelopeFixtures::sealedEnvelope(),
        ];

        $this->actingAs($user)
            ->post('/account/identity', rotationPayload($user, ['memberships' => $memberships]))
            ->assertSessionHasErrors('memberships');
    });

    /*
     | A revoked membership's sealed key opens nothing this user is entitled to,
     | so carrying it across would re-seal access that was deliberately
     | withdrawn. The row survives as a record, not as a key.
     */
    it('excludes revoked memberships from the required set', function () {
        $user = rotatingUser(vaults: 2);
        $revoked = $user->vaultMemberships()->first();
        $revoked?->forceFill(['revoked_at' => now()])->save();

        expect(rotationMemberships($user))->toHaveCount(1);

        $this->actingAs($user)->post('/account/identity', rotationPayload($user))->assertRedirect();

        expect(AuditEvent::query()->where('action', AuditAction::IdentityRotated)->sole()->metadata)
            ->toBe('{"count":1}');
    });

    it('accepts an empty set from somebody in no vaults', function () {
        $user = rotatingUser();

        $this->actingAs($user)
            ->post('/account/identity', rotationPayload($user, ['memberships' => []]))
            ->assertRedirect();

        expect(UserIdentityArchive::query()->count())->toBe(1);
    });
});

describe('the certificate check', function () {
    /*
     | Not security: a malicious server would skip it, and the signature is
     | deliberately not verified here at all — the server publishes the key it
     | would check against. It catches a client that built the notice wrong, at
     | the moment the mistake is made, instead of leaving peers to discover it
     | weeks later as an unexplained hard stop.
     */
    it('refuses a notice naming the wrong outgoing fingerprint', function () {
        $user = rotatingUser();

        $this->actingAs($user)
            ->post('/account/identity', rotationPayload($user, [
                'rotation_payload' => json_encode([
                    'v' => 1,
                    'userUuid' => $user->uuid,
                    'previousFingerprint' => str_repeat('a', 64),
                    'fingerprint' => str_repeat('b', 64),
                    'rotatedAt' => '2026-08-16T09:00:00Z',
                ], JSON_THROW_ON_ERROR),
            ]))
            ->assertSessionHasErrors('rotation_payload');
    });

    it('refuses a notice about a different account', function () {
        $user = rotatingUser();

        $this->actingAs($user)
            ->post('/account/identity', rotationPayload($user, [
                'rotation_payload' => json_encode([
                    'v' => 1,
                    'userUuid' => (string) Str::uuid7(),
                    'previousFingerprint' => currentFingerprintHex($user),
                    'fingerprint' => str_repeat('b', 64),
                    'rotatedAt' => '2026-08-16T09:00:00Z',
                ], JSON_THROW_ON_ERROR),
            ]))
            ->assertSessionHasErrors('rotation_payload');
    });
});

describe('what peers are served afterwards', function () {
    /*
     | The certificate has to travel with the keys, or a peer sees a changed
     | fingerprint with nothing to distinguish a rotation from a substitution —
     | which is the one screen this whole mechanism exists to soften.
     */
    it('publishes the retired keys and the notice beside the new ones', function () {
        $user = rotatingUser();
        $user->forceFill(['handle' => 'ada'])->save();
        $retired = $user->identity?->fingerprint->base64;
        $fingerprint = base64_encode(random_bytes(32));

        $certificate = json_encode([
            'v' => 1,
            'userUuid' => $user->uuid,
            'previousFingerprint' => currentFingerprintHex($user),
            'fingerprint' => bin2hex((string) base64_decode($fingerprint, true)),
            'rotatedAt' => '2026-08-16T09:00:00Z',
        ], JSON_THROW_ON_ERROR);

        $this->actingAs($user)->post('/account/identity', rotationPayload($user, [
            'fingerprint' => $fingerprint,
            'rotation_payload' => $certificate,
        ]))->assertRedirect();

        $response = $this->actingAs(User::factory()->create())
            ->getJson('/users/ada/identity')
            ->assertOk();

        expect($response->json('fingerprint'))->toBe($fingerprint)
            ->and($response->json('rotation.fingerprint'))->toBe($retired)
            ->and($response->json('rotation.payload'))->toBe($certificate);
    });

    /*
     | The owner's own client needs these: a grant names the fingerprint it was
     | issued for, so without them every grant made before a rotation would fail
     | to verify and every shared vault would render as a warning.
     */
    it('tells the owner which fingerprints they used to have', function () {
        $user = rotatingUser();
        $first = $user->identity?->fingerprint->bytes();

        $this->actingAs($user)->post('/account/identity', rotationPayload($user));

        $this->actingAs($user->refresh())
            ->get('/vaults')
            ->assertInertia(fn (AssertableInertia $page) => $page->where(
                'auth.previousFingerprints',
                [bin2hex((string) $first)],
            ));
    });
});

describe('the page', function () {
    it('lists every key that will move, and the account\'s own KDF state', function () {
        Config::set('vault.kdf', ['m' => 65536, 't' => 3, 'p' => 1]);

        $user = rotatingUser(vaults: 2);
        $user->forceFill(['kdf_params' => ['m' => 16384, 't' => 2, 'p' => 1]])->save();

        $this->actingAs($user)
            ->get('/account/identity')
            ->assertOk()
            ->assertInertia(fn (AssertableInertia $page) => $page
                ->has('memberships', 2)
                ->where('kdf.behind', true)
                ->where('kdf.target', ['m' => 65536, 't' => 3, 'p' => 1]));
    });

    /*
     | A partial list would produce a partial submission, which the server
     | refuses — correctly, and after the user has waited. So the page is served
     | whole or not at all.
     */
    it('leaves out memberships that were revoked', function () {
        $user = rotatingUser(vaults: 2);
        $user->vaultMemberships()->first()?->forceFill(['revoked_at' => now()])->save();

        $this->actingAs($user)
            ->get('/account/identity')
            ->assertInertia(fn (AssertableInertia $page) => $page->has('memberships', 1));
    });
});

describe('who may rotate', function () {
    it('is not reachable without a session', function () {
        $this->post('/account/identity', [])->assertRedirect('/login');
    });

    it('refuses an account with no published keys', function () {
        $user = User::factory()->create();

        $this->actingAs($user)
            ->post('/account/identity', [
                'x25519_public_key' => base64_encode(random_bytes(32)),
                'ed25519_public_key' => base64_encode(random_bytes(32)),
                'x25519_private_key_ct' => EnvelopeFixtures::envelope(48),
                'ed25519_private_key_ct' => EnvelopeFixtures::envelope(48),
                'self_signature' => base64_encode(random_bytes(64)),
                'fingerprint' => base64_encode(random_bytes(32)),
                'rotation_payload' => '{}',
                'rotation_signature' => base64_encode(random_bytes(64)),
                'memberships' => [],
            ])
            ->assertSessionHasErrors('fingerprint');
    });

    /*
     | An identity belongs to exactly one account and this rotates the caller's
     | own, so there is no identifier in the request that could name somebody
     | else's — asserted rather than assumed, because "there is no parameter to
     | abuse" is the kind of claim that stops being true when one gets added.
     */
    it('cannot be aimed at another account', function () {
        $victim = rotatingUser();
        $attacker = rotatingUser();
        $before = $victim->identity?->fingerprint->base64;

        $this->actingAs($attacker)
            ->post('/account/identity', rotationPayload($attacker))
            ->assertRedirect();

        expect($victim->refresh()->identity?->fingerprint->base64)->toBe($before);
    });
});
