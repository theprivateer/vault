<?php

use App\Enums\VaultRole;
use App\Models\Lockbox;
use App\Models\Secret;
use App\Models\User;
use App\Models\UserIdentity;
use App\Models\Vault;
use Database\Factories\EnvelopeFixtures;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Inertia\Testing\AssertableInertia;

/**
 * Granting, accepting and revoking, from the server's side.
 *
 * The cryptographic half of sharing is tested in the browser suite, where real
 * keys exist — `resources/js/lib/sharing.test.ts` covers signature verification
 * and the key-substitution hard stop. What is tested here is everything the
 * server is actually responsible for: that it stores exactly what it was given,
 * that access is cut the instant a membership is revoked, and that it never
 * pretends to have checked something it cannot check.
 */

/**
 * @param  array<string, mixed>  $overrides
 * @return array<string, mixed>
 */
function grantPayload(Vault $vault, User $recipient, array $overrides = []): array
{
    $grant = [
        'v' => 1,
        'vaultUuid' => $vault->uuid,
        'recipientUuid' => $recipient->uuid,
        'recipientFingerprint' => str_repeat('a', 64),
        'role' => 'editor',
        'keyEpoch' => $vault->key_epoch,
        'grantedAt' => '2026-08-15T09:00:00Z',
    ];

    return [
        'membership_uuid' => (string) Str::uuid7(),
        'user_uuid' => $recipient->uuid,
        'role' => $grant['role'],
        'wrapped_vault_key' => EnvelopeFixtures::sealedEnvelope(),
        'grant_signature' => base64_encode(random_bytes(64)),
        'grant_payload' => json_encode($grant),
        ...$overrides,
    ];
}

function recipientWithKeys(): User
{
    $user = User::factory()->create();
    UserIdentity::factory()->for($user)->create();

    return $user;
}

describe('granting', function () {
    it('stores the sealed key and the signed grant', function () {
        $owner = User::factory()->create();
        $vault = Vault::factory()->ownedBy($owner)->create();
        $recipient = recipientWithKeys();

        $payload = grantPayload($vault, $recipient);

        $this->actingAs($owner)
            ->post("/vaults/{$vault->uuid}/memberships", $payload)
            ->assertRedirect();

        $membership = $vault->memberships()->where('user_id', $recipient->getKey())->sole();

        expect($membership->role)->toBe(VaultRole::Editor)
            ->and($membership->wrapped_vault_key->base64)
            ->toBe(payloadString($payload, 'wrapped_vault_key'))
            ->and($membership->key_epoch)->toBe($vault->key_epoch)
            ->and($membership->granted_by)->toBe($owner->getKey())
            ->and($membership->accepted_at)->toBeNull();
    });

    /**
     * The signature covers these exact bytes. A round trip through
     * json_decode/json_encode is free to change them — the escaping of `/`, of
     * non-ASCII, of anything a later field introduces — and every such change
     * turns a valid grant into one no recipient can verify, failing in a way
     * that looks exactly like tampering.
     *
     * Asserted against the raw column, because reading it back through the
     * model would only prove the model returns what the model stored.
     */
    it('stores the grant payload byte for byte', function () {
        $owner = User::factory()->create();
        $vault = Vault::factory()->ownedBy($owner)->create();
        $recipient = recipientWithKeys();

        // Contains a `/` and a non-ASCII character, both of which PHP's
        // json_encode escapes by default and the client's does not.
        $grant = json_encode([
            'v' => 1,
            'vaultUuid' => $vault->uuid,
            'recipientUuid' => $recipient->uuid,
            'recipientFingerprint' => str_repeat('b', 64),
            'role' => 'viewer',
            'keyEpoch' => $vault->key_epoch,
            'grantedAt' => '2026-08-15T09:00:00Z',
            'note' => 'a/b — ü',
        ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        // Without this the test proves nothing: the two encodings must differ.
        expect($grant)->not->toBe(json_encode(json_decode((string) $grant, true)));

        $payload = grantPayload($vault, $recipient, ['role' => 'viewer', 'grant_payload' => $grant]);

        $this->actingAs($owner)
            ->post("/vaults/{$vault->uuid}/memberships", $payload)
            ->assertRedirect();

        $stored = DB::table('vault_memberships')
            ->where('uuid', payloadString($payload, 'membership_uuid'))
            ->value('grant_payload');

        expect($stored)->toBe($grant);
    });

    it('refuses a grant that disagrees with the request it arrived in', function () {
        $owner = User::factory()->create();
        $vault = Vault::factory()->ownedBy($owner)->create();
        $recipient = recipientWithKeys();

        // Signed as a viewer, requested as an editor. No recipient could ever
        // accept this, so it is refused at the door rather than stored.
        $grant = json_encode([
            'v' => 1,
            'vaultUuid' => $vault->uuid,
            'recipientUuid' => $recipient->uuid,
            'recipientFingerprint' => str_repeat('a', 64),
            'role' => 'viewer',
            'keyEpoch' => $vault->key_epoch,
            'grantedAt' => '2026-08-15T09:00:00Z',
        ]);

        $this->actingAs($owner)
            ->post("/vaults/{$vault->uuid}/memberships", grantPayload($vault, $recipient, [
                'role' => 'editor',
                'grant_payload' => $grant,
            ]))
            ->assertSessionHasErrors('grant_payload');

        expect($vault->memberships()->where('user_id', $recipient->getKey())->exists())->toBeFalse();
    });

    it('rejects a grant with no signature at all', function () {
        $owner = User::factory()->create();
        $vault = Vault::factory()->ownedBy($owner)->create();
        $recipient = recipientWithKeys();

        $payload = grantPayload($vault, $recipient);
        unset($payload['grant_signature']);

        $this->actingAs($owner)
            ->post("/vaults/{$vault->uuid}/memberships", $payload)
            ->assertSessionHasErrors('grant_signature');
    });

    /**
     * A second owner arriving through the sharing path would leave `vaults.owner_id`
     * and the membership rows disagreeing about who the owner is. Transfer is
     * its own operation.
     */
    it('refuses to grant the owner role', function () {
        $owner = User::factory()->create();
        $vault = Vault::factory()->ownedBy($owner)->create();
        $recipient = recipientWithKeys();

        $this->actingAs($owner)
            ->post("/vaults/{$vault->uuid}/memberships", grantPayload($vault, $recipient, ['role' => 'owner']))
            ->assertSessionHasErrors('role');
    });

    it('refuses to share with an account that has published no keys', function () {
        $owner = User::factory()->create();
        $vault = Vault::factory()->ownedBy($owner)->create();
        $recipient = User::factory()->create();

        $this->actingAs($owner)
            ->post("/vaults/{$vault->uuid}/memberships", grantPayload($vault, $recipient))
            ->assertSessionHasErrors('user_uuid');
    });

    /**
     * Re-granting has to reuse the row — (vault, user) is unique — and the thing
     * that must not be reused is `accepted_at`. The reason someone was removed
     * may be the reason their keys should not be trusted, so a returning member
     * verifies again.
     */
    it('clears the acceptance when re-granting to somebody previously revoked', function () {
        $owner = User::factory()->create();
        $vault = Vault::factory()->ownedBy($owner)->create();
        $recipient = recipientWithKeys();

        $this->actingAs($owner)->post("/vaults/{$vault->uuid}/memberships", grantPayload($vault, $recipient));

        $membership = $vault->memberships()->where('user_id', $recipient->getKey())->sole();
        $membership->forceFill(['accepted_at' => now(), 'revoked_at' => now()])->save();

        $this->actingAs($owner)
            ->post("/vaults/{$vault->uuid}/memberships", grantPayload($vault, $recipient))
            ->assertRedirect();

        $membership->refresh();

        expect($membership->revoked_at)->toBeNull()
            ->and($membership->accepted_at)->toBeNull();
    });
});

describe('revoking', function () {
    /**
     * Two things in one transaction, and they are different kinds of thing.
     * Cutting access is instant and enforceable. Rotating the key needs an
     * owner's browser, so it is recorded as a requirement rather than done here.
     */
    it('cuts access immediately and marks the vault as needing a new key', function () {
        $owner = User::factory()->create();
        $vault = Vault::factory()->ownedBy($owner)->create();
        $member = User::factory()->create();

        $membership = $vault->memberships()->create([
            'uuid' => (string) Str::uuid7(),
            'user_id' => $member->getKey(),
            'role' => VaultRole::Editor,
            'wrapped_vault_key' => EnvelopeFixtures::sealedEnvelope(),
            'key_epoch' => $vault->key_epoch,
            'granted_by' => $owner->getKey(),
        ]);

        $this->actingAs($member)->get("/vaults/{$vault->uuid}")->assertOk();

        $this->actingAs($owner)->delete("/memberships/{$membership->uuid}")->assertRedirect();

        // Before any re-key has happened.
        $this->actingAs($member)->get("/vaults/{$vault->uuid}")->assertNotFound();

        expect($vault->refresh()->rekey_required_at)->not->toBeNull();
    });

    it('drops the vault out of the removed member\'s list', function () {
        $owner = User::factory()->create();
        $vault = Vault::factory()->ownedBy($owner)->create();
        $member = User::factory()->create();

        $membership = $vault->memberships()->create([
            'uuid' => (string) Str::uuid7(),
            'user_id' => $member->getKey(),
            'role' => VaultRole::Viewer,
            'wrapped_vault_key' => EnvelopeFixtures::sealedEnvelope(),
            'key_epoch' => $vault->key_epoch,
            'granted_by' => $owner->getKey(),
        ]);

        $this->actingAs($owner)->delete("/memberships/{$membership->uuid}");

        $this->actingAs($member)
            ->get('/vaults')
            ->assertInertia(fn (AssertableInertia $page) => $page->has('vaults', 0));
    });
});

describe('the identity directory', function () {
    it('publishes the public keys and the self-signature, and nothing private', function () {
        $user = User::factory()->create(['handle' => 'ada']);
        $identity = UserIdentity::factory()->for($user)->create();

        $response = $this->actingAs(User::factory()->create())
            ->getJson('/users/ada/identity')
            ->assertOk();

        expect($response->json())->toBe([
            'uuid' => $user->uuid,
            'displayName' => $user->display_name,
            'handle' => 'ada',
            'x25519PublicKey' => $identity->x25519_public_key->base64,
            'ed25519PublicKey' => $identity->ed25519_public_key->base64,
            'selfSignature' => $identity->self_signature->base64,
            'fingerprint' => $identity->fingerprint->base64,
        ]);
    });

    /**
     * An account with no published keys cannot be shared with, and neither can
     * one that does not exist. Two different negatives would be a distinction
     * worth probing for, so they answer identically.
     */
    it('answers 404 identically for an unknown handle and one with no keys', function () {
        User::factory()->create(['handle' => 'keyless']);
        $actor = User::factory()->create();

        $this->actingAs($actor)->getJson('/users/keyless/identity')->assertNotFound();
        $this->actingAs($actor)->getJson('/users/nobody/identity')->assertNotFound();
    });

    it('requires a session', function () {
        $user = User::factory()->create(['handle' => 'ada']);
        UserIdentity::factory()->for($user)->create();

        $this->get('/users/ada/identity')->assertRedirect('/login');
    });
});

describe('the pin store', function () {
    it('hands back exactly the blob it was given', function () {
        $user = User::factory()->create();
        $blob = EnvelopeFixtures::envelope(96);

        $this->actingAs($user)
            ->postJson('/account/pins', ['pins_ct' => $blob, 'expected_version' => 0])
            ->assertOk()
            ->assertJson(['version' => 1]);

        expect($user->refresh()->pinBundle())->toBe(['pinsCt' => $blob, 'version' => 1]);
    });

    it('refuses a write composed against a version that has moved on', function () {
        $user = User::factory()->create();

        $this->actingAs($user)->postJson('/account/pins', [
            'pins_ct' => EnvelopeFixtures::envelope(96),
            'expected_version' => 0,
        ])->assertOk();

        $second = EnvelopeFixtures::envelope(96);

        $this->actingAs($user)
            ->postJson('/account/pins', ['pins_ct' => $second, 'expected_version' => 0])
            ->assertStatus(422)
            ->assertJsonValidationErrors('expected_version');

        expect($user->refresh()->pinBundle()['pinsCt'])->not->toBe($second);
    });

    it('is nobody else\'s to read', function () {
        $user = User::factory()->create();
        $blob = EnvelopeFixtures::envelope(96);

        $this->actingAs($user)->postJson('/account/pins', ['pins_ct' => $blob, 'expected_version' => 0]);

        $stranger = User::factory()->create();

        expect($stranger->pinBundle())->toBe(['pinsCt' => null, 'version' => 0]);
    });

    it('rejects anything that is not a well-formed envelope', function () {
        $this->actingAs(User::factory()->create())
            ->postJson('/account/pins', ['pins_ct' => 'not-an-envelope', 'expected_version' => 0])
            ->assertStatus(422)
            ->assertJsonValidationErrors('pins_ct');
    });
});

/**
 * The leak canary's question, asked of the sharing tables: does any of this put
 * plaintext somewhere it was not before?
 */
it('adds no readable content to the memberships table', function () {
    $owner = User::factory()->create();
    $vault = Vault::factory()->ownedBy($owner)->create();
    $lockbox = Lockbox::factory()->for($vault)->create();
    Secret::factory()->for($lockbox)->create();
    $recipient = recipientWithKeys();

    $this->actingAs($owner)->post("/vaults/{$vault->uuid}/memberships", grantPayload($vault, $recipient));

    $row = (array) DB::table('vault_memberships')
        ->where('user_id', $recipient->getKey())
        ->first();

    /*
     | `grant_payload` is plaintext, deliberately and unavoidably: the recipient
     | has to read it to verify the signature over it. What it may contain is
     | therefore fixed, and this asserts the set — a future field carrying
     | anything about the vault's *contents* would fail here.
     */
    $grantPayload = $row['grant_payload'] ?? null;

    expect(array_keys((array) json_decode(is_string($grantPayload) ? $grantPayload : '', true)))
        ->toBe(['v', 'vaultUuid', 'recipientUuid', 'recipientFingerprint', 'role', 'keyEpoch', 'grantedAt']);
});
