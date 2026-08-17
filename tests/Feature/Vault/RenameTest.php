<?php

use App\Enums\AuditAction;
use App\Enums\VaultRole;
use App\Models\AuditEvent;
use App\Models\Lockbox;
use App\Models\Secret;
use App\Models\User;
use App\Models\Vault;
use App\Models\VaultMembership;
use Database\Factories\EnvelopeFixtures;

/**
 * Renaming a vault and a lockbox — `PATCH /vaults/{vault}` and
 * `PATCH /lockboxes/{lockbox}`.
 *
 * **Both endpoints shipped in Phase 3 and neither had a test or a caller.**
 * Route, policy, form request and audit action all present; no interface reached
 * either one, and nothing here asserted them. From inside the repository that is
 * indistinguishable from a finished feature, which is why it survived ten phases
 * and was found by somebody trying to fix a typo.
 *
 * There is no server-side "name" to check, because the server has never seen
 * one: a rename is a re-encryption of the whole payload under a fresh Item Key,
 * exactly like an edit to a secret. So these tests assert what the server can
 * actually be responsible for — that the blobs are replaced, that the right
 * people may do it, and that it is recorded.
 */
/**
 * @param  array<string, mixed>  $overrides
 * @return array<string, mixed>
 */
function renamePayload(array $overrides = []): array
{
    return [
        'payload_ct' => EnvelopeFixtures::envelope(120),
        'wrapped_item_key' => EnvelopeFixtures::envelope(48),
        'payload_version' => 2,
        ...$overrides,
    ];
}

describe('renaming a vault', function () {
    it('replaces the payload and its item key', function () {
        $user = User::factory()->create();
        $vault = Vault::factory()->ownedBy($user)->create();
        $before = $vault->payload_ct->base64;
        $payload = renamePayload();

        $this->actingAs($user)->patch("/vaults/{$vault->uuid}", $payload)->assertRedirect();

        $vault->refresh();

        expect($vault->payload_ct->base64)->toBe(payloadString($payload, 'payload_ct'))
            ->and($vault->payload_ct->base64)->not->toBe($before)
            /*
             | The fresh Item Key matters as much as the payload. Re-using the
             | old one would encrypt two different plaintexts under one key,
             | which is the rule every write here follows.
             */
            ->and($vault->wrapped_item_key->base64)->toBe(payloadString($payload, 'wrapped_item_key'));
    });

    it('records it, under the action whose description says "renamed this vault"', function () {
        $user = User::factory()->create();
        $vault = Vault::factory()->ownedBy($user)->create();

        $this->actingAs($user)->patch("/vaults/{$vault->uuid}", renamePayload());

        expect(AuditEvent::query()->where('action', AuditAction::VaultUpdated)->count())->toBe(1);
    });

    /*
     | `VaultPolicy::update` is `canWrite`, so this is an editor's ability and
     | not an owner's — the same one that lets them add a lockbox. Worth pinning:
     | the interface shows the panel on exactly this rule, and a policy change
     | that quietly narrowed it would leave a control that 404s.
     */
    it('is allowed to an editor', function () {
        $user = User::factory()->create();
        $vault = Vault::factory()->create();
        VaultMembership::factory()->for($vault)->for($user)->role(VaultRole::Editor)->create();

        $this->actingAs($user)->patch("/vaults/{$vault->uuid}", renamePayload())->assertRedirect();
    });

    it('is refused to a viewer, as a 404 rather than a 403', function () {
        $user = User::factory()->create();
        $vault = Vault::factory()->create();
        VaultMembership::factory()->for($vault)->for($user)->role(VaultRole::Viewer)->create();

        $this->actingAs($user)->patch("/vaults/{$vault->uuid}", renamePayload())->assertNotFound();
    });

    it('is refused to a stranger, who learns nothing about whether it exists', function () {
        $vault = Vault::factory()->create();

        $this->actingAs(User::factory()->create())
            ->patch("/vaults/{$vault->uuid}", renamePayload())
            ->assertNotFound();
    });

    it('refuses a payload that is not a recognised envelope', function () {
        $user = User::factory()->create();
        $vault = Vault::factory()->ownedBy($user)->create();

        $this->actingAs($user)
            ->patch("/vaults/{$vault->uuid}", renamePayload(['payload_ct' => 'not-an-envelope']))
            ->assertSessionHasErrors('payload_ct');
    });

    /*
     | A rename changes the vault record and nothing else. Every item key in the
     | vault stays wrapped by the same Vault Key, so no secret is touched — which
     | is the difference between this and a re-key, and the reason the panel says
     | so out loud.
     */
    it('leaves every secret in the vault alone', function () {
        $user = User::factory()->create();
        $vault = Vault::factory()->ownedBy($user)->create();
        $lockbox = Lockbox::factory()->for($vault)->create();
        $secret = Secret::factory()->for($lockbox)->create();

        $before = [$secret->payload_ct->base64, $secret->wrapped_item_key->base64, $secret->current_version];

        $this->actingAs($user)->patch("/vaults/{$vault->uuid}", renamePayload());

        $secret->refresh();

        expect([$secret->payload_ct->base64, $secret->wrapped_item_key->base64, $secret->current_version])
            ->toBe($before)
            ->and($vault->refresh()->key_epoch)->toBe(1);
    });
});

describe('renaming a lockbox', function () {
    it('replaces the payload and its item key', function () {
        $user = User::factory()->create();
        $lockbox = writableLockbox($user);
        $payload = renamePayload();

        $this->actingAs($user)->patch("/lockboxes/{$lockbox->uuid}", $payload)->assertRedirect();

        $lockbox->refresh();

        expect($lockbox->payload_ct->base64)->toBe(payloadString($payload, 'payload_ct'))
            ->and($lockbox->wrapped_item_key->base64)->toBe(payloadString($payload, 'wrapped_item_key'));
    });

    it('records it', function () {
        $user = User::factory()->create();
        $lockbox = writableLockbox($user);

        $this->actingAs($user)->patch("/lockboxes/{$lockbox->uuid}", renamePayload());

        expect(AuditEvent::query()->where('action', AuditAction::LockboxUpdated)->count())->toBe(1);
    });

    it('is refused to a viewer, as a 404', function () {
        $user = User::factory()->create();
        $vault = Vault::factory()->create();
        VaultMembership::factory()->for($vault)->for($user)->role(VaultRole::Viewer)->create();
        $lockbox = Lockbox::factory()->for($vault)->create();

        $this->actingAs($user)->patch("/lockboxes/{$lockbox->uuid}", renamePayload())->assertNotFound();
    });

    it('leaves the secrets inside it alone', function () {
        $user = User::factory()->create();
        $lockbox = writableLockbox($user);
        $secret = Secret::factory()->for($lockbox)->create();
        $before = $secret->payload_ct->base64;

        $this->actingAs($user)->patch("/lockboxes/{$lockbox->uuid}", renamePayload());

        expect($secret->refresh()->payload_ct->base64)->toBe($before);
    });
});
