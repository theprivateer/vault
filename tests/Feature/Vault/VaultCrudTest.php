<?php

use App\Enums\VaultRole;
use App\Models\Lockbox;
use App\Models\Secret;
use App\Models\User;
use App\Models\Vault;
use Database\Factories\EnvelopeFixtures;
use Illuminate\Support\Str;
use Inertia\Testing\AssertableInertia;

/**
 * @param  array<string, mixed>  $overrides
 * @return array<string, mixed>
 */
function vaultPayload(array $overrides = []): array
{
    return [
        'uuid' => (string) Str::uuid7(),
        'membership_uuid' => (string) Str::uuid7(),
        'payload_ct' => EnvelopeFixtures::envelope(96),
        'wrapped_item_key' => EnvelopeFixtures::envelope(48),
        'wrapped_vault_key' => EnvelopeFixtures::sealedEnvelope(),
        'payload_version' => 1,
        ...$overrides,
    ];
}

/**
 * @param  array<string, mixed>  $overrides
 * @return array<string, mixed>
 */
function itemPayload(array $overrides = []): array
{
    return [
        'uuid' => (string) Str::uuid7(),
        'payload_ct' => EnvelopeFixtures::envelope(96),
        'wrapped_item_key' => EnvelopeFixtures::envelope(48),
        'payload_version' => 1,
        ...$overrides,
    ];
}

describe('creating a vault', function () {
    it('stores the blobs and the creator membership in one transaction', function () {
        $user = User::factory()->create();
        $payload = vaultPayload();

        $this->actingAs($user)->post('/vaults', $payload)->assertRedirect();

        $vault = Vault::query()->where('uuid', payloadString($payload, 'uuid'))->sole();

        expect($vault->payload_ct->base64)->toBe(payloadString($payload, 'payload_ct'))
            ->and($vault->owner_id)->toBe($user->getKey())
            ->and($vault->key_epoch)->toBe(1);

        $membership = $vault->memberships()->sole();

        expect($membership->role)->toBe(VaultRole::Owner)
            ->and($membership->wrapped_vault_key->base64)->toBe(payloadString($payload, 'wrapped_vault_key'))
            ->and($membership->key_epoch)->toBe($vault->key_epoch);
    });

    /*
     | The Vault Key exists in exactly one place: sealed on a membership row.
     | A vault without one would be permanently unreadable, including by its
     | own creator, and no amount of server-side repair could fix it.
     */
    it('creates nothing at all when the membership is rejected', function () {
        $user = User::factory()->create();

        $this->actingAs($user)
            ->post('/vaults', vaultPayload(['wrapped_vault_key' => 'not-an-envelope']))
            ->assertSessionHasErrors('wrapped_vault_key');

        expect(Vault::query()->count())->toBe(0);
    });

    it('rejects a uuid that is not version 7', function () {
        $user = User::factory()->create();

        $this->actingAs($user)
            ->post('/vaults', vaultPayload(['uuid' => (string) Str::uuid()]))
            ->assertSessionHasErrors('uuid');
    });

    it('rejects a uuid that is already taken', function () {
        $user = User::factory()->create();
        $existing = Vault::factory()->ownedBy($user)->create();

        $this->actingAs($user)
            ->post('/vaults', vaultPayload(['uuid' => $existing->uuid]))
            ->assertSessionHasErrors('uuid');
    });

    it('rejects a payload version this build does not write', function () {
        $user = User::factory()->create();

        $this->actingAs($user)
            ->post('/vaults', vaultPayload(['payload_version' => 99]))
            ->assertSessionHasErrors('payload_version');
    });

    /*
     | A downgrade attempt fails at the edge rather than being stored and
     | discovered by a browser later. The header is public metadata, so reading
     | two bytes of it is not a step towards reading the payload.
     */
    it('rejects an envelope whose algorithm byte is unknown', function () {
        $user = User::factory()->create();

        $this->actingAs($user)
            ->post('/vaults', vaultPayload([
                'payload_ct' => base64_encode(chr(1).chr(9).random_bytes(48)),
            ]))
            ->assertSessionHasErrors('payload_ct');
    });

    it('rejects a payload above the size cap', function () {
        $user = User::factory()->create();

        $this->actingAs($user)
            ->post('/vaults', vaultPayload([
                'payload_ct' => EnvelopeFixtures::envelope(config()->integer('vault.max_payload_bytes') + 1),
            ]))
            ->assertSessionHasErrors('payload_ct');
    });
});

describe('listing and reading', function () {
    it('lists only vaults the user holds a live membership for', function () {
        $user = User::factory()->create();
        $mine = Vault::factory()->ownedBy($user)->create();
        Vault::factory()->ownedBy(User::factory()->create())->create();

        $this->actingAs($user)
            ->get('/vaults')
            ->assertInertia(fn (AssertableInertia $page) => $page
                ->component('vaults/Index')
                ->has('vaults', 1)
                ->where('vaults.0.uuid', $mine->uuid)
            );
    });

    it('ships the ciphertext and the membership key, and no associated data', function () {
        $user = User::factory()->create();
        $vault = Vault::factory()->ownedBy($user)->create();
        $membership = $vault->memberships()->sole();

        $this->actingAs($user)
            ->get('/vaults')
            ->assertInertia(fn (AssertableInertia $page) => $page
                ->where('vaults.0.payloadCt', $vault->payload_ct->base64)
                ->where('vaults.0.membership.wrappedVaultKey', $membership->wrapped_vault_key->base64)
                ->where('vaults.0.membership.role', 'owner')
                // The client builds its own AAD. A server that supplied it
                // could tell the client to verify against the wrong record.
                ->missing('vaults.0.aad')
            );
    });

    it('shows a vault with its lockboxes and their secret counts', function () {
        $user = User::factory()->create();
        $vault = Vault::factory()->ownedBy($user)->create();
        $lockbox = Lockbox::factory()->for($vault)->create();
        Secret::factory()->for($lockbox)->count(3)->create();

        $this->actingAs($user)
            ->get("/vaults/{$vault->uuid}")
            ->assertInertia(fn (AssertableInertia $page) => $page
                ->component('vaults/Show')
                ->where('vault.uuid', $vault->uuid)
                ->has('lockboxes', 1)
                ->where('lockboxes.0.secretCount', 3)
            );
    });

    /*
     | The whole vault, not a page of it.
     |
     | Search runs in the browser because the server cannot read a name (D5),
     | so a paginated response would either mean the server can read them or
     | mean the results are wrong. The cost of sending everything is measured
     | rather than assumed — see the scale ceiling in docs/06.
     */
    it('sends every secret in the vault, not only one lockbox worth', function () {
        $user = User::factory()->create();
        $vault = Vault::factory()->ownedBy($user)->create();

        $first = Lockbox::factory()->for($vault)->create();
        $second = Lockbox::factory()->for($vault)->create();

        Secret::factory()->for($first)->count(2)->create();
        Secret::factory()->for($second)->count(3)->create();

        // A vault the user also owns, whose contents must not appear here.
        Secret::factory()
            ->for(Lockbox::factory()->for(Vault::factory()->ownedBy($user)))
            ->create();

        $this->actingAs($user)
            ->get("/vaults/{$vault->uuid}")
            ->assertInertia(fn (AssertableInertia $page) => $page
                ->has('secrets', 5)
                ->where('secrets.0.lockboxUuid', $first->uuid)
            );
    });

    it('drops a vault from the list once it is deleted', function () {
        $user = User::factory()->create();
        $vault = Vault::factory()->ownedBy($user)->create();

        $this->actingAs($user)->delete("/vaults/{$vault->uuid}")->assertRedirect('/vaults');

        $this->actingAs($user)
            ->get('/vaults')
            ->assertInertia(fn (AssertableInertia $page) => $page->has('vaults', 0));

        // Soft deleted: the 30-day grace period in docs/04-data-model.md.
        expect(Vault::withTrashed()->count())->toBe(1);
    });
});

describe('updating', function () {
    it('replaces the payload and the item key together', function () {
        $user = User::factory()->create();
        $vault = Vault::factory()->ownedBy($user)->create();

        $update = [
            'payload_ct' => EnvelopeFixtures::envelope(120),
            'wrapped_item_key' => EnvelopeFixtures::envelope(48),
            'payload_version' => 1,
        ];

        $this->actingAs($user)->patch("/vaults/{$vault->uuid}", $update)->assertRedirect();

        $vault->refresh();

        expect($vault->payload_ct->base64)->toBe(payloadString($update, 'payload_ct'))
            ->and($vault->wrapped_item_key->base64)->toBe(payloadString($update, 'wrapped_item_key'));
    });

    /*
     | The identifier is bound into the associated data of the ciphertext being
     | submitted. Accepting a second copy in the body would admit a mismatch
     | that only surfaced later, as an integrity error in someone's browser.
     */
    it('ignores a uuid in the body', function () {
        $user = User::factory()->create();
        $vault = Vault::factory()->ownedBy($user)->create();
        $original = $vault->uuid;

        $this->actingAs($user)->patch("/vaults/{$vault->uuid}", [
            'uuid' => (string) Str::uuid7(),
            'payload_ct' => EnvelopeFixtures::envelope(120),
            'wrapped_item_key' => EnvelopeFixtures::envelope(48),
            'payload_version' => 1,
        ])->assertRedirect();

        expect($vault->refresh()->uuid)->toBe($original);
    });
});

describe('lockboxes and secrets', function () {
    it('creates a lockbox inside a vault resolved from the route', function () {
        $user = User::factory()->create();
        $vault = Vault::factory()->ownedBy($user)->create();
        $payload = itemPayload(['sort_order' => 2]);

        $this->actingAs($user)->post("/vaults/{$vault->uuid}/lockboxes", $payload)->assertRedirect();

        $lockbox = $vault->lockboxes()->sole();

        expect($lockbox->uuid)->toBe(payloadString($payload, 'uuid'))
            ->and($lockbox->sort_order)->toBe(2);
    });

    it('creates a secret inside a lockbox resolved from the route', function () {
        $user = User::factory()->create();
        $vault = Vault::factory()->ownedBy($user)->create();
        $lockbox = Lockbox::factory()->for($vault)->create();
        $payload = itemPayload();

        $this->actingAs($user)->post("/lockboxes/{$lockbox->uuid}/secrets", $payload)->assertRedirect();

        expect($lockbox->secrets()->sole()->uuid)->toBe(payloadString($payload, 'uuid'));
    });

    it('links a secret to another lockbox in the same vault', function () {
        $user = User::factory()->create();
        $vault = Vault::factory()->ownedBy($user)->create();
        $lockbox = Lockbox::factory()->for($vault)->create();
        $target = Lockbox::factory()->for($vault)->create();

        $this->actingAs($user)
            ->post("/lockboxes/{$lockbox->uuid}/secrets", itemPayload([
                'linked_lockbox_uuid' => $target->uuid,
            ]))
            ->assertRedirect();

        expect($lockbox->secrets()->sole()->linked_lockbox_id)->toBe($target->getKey());
    });

    /*
     | The link is the one field on these tables that names another record, so
     | it is the one place a cross-vault reference could be smuggled in. A
     | lockbox in another vault must be as unusable as one that does not exist.
     */
    it('refuses to link a secret to a lockbox in another vault', function () {
        $user = User::factory()->create();
        $vault = Vault::factory()->ownedBy($user)->create();
        $lockbox = Lockbox::factory()->for($vault)->create();

        $elsewhere = Lockbox::factory()
            ->for(Vault::factory()->ownedBy($user))
            ->create();

        $this->actingAs($user)
            ->post("/lockboxes/{$lockbox->uuid}/secrets", itemPayload([
                'linked_lockbox_uuid' => $elsewhere->uuid,
            ]))
            ->assertSessionHasErrors('linked_lockbox_uuid');

        expect($lockbox->secrets()->count())->toBe(0);
    });

    it('deletes a secret without touching its siblings', function () {
        $user = User::factory()->create();
        $vault = Vault::factory()->ownedBy($user)->create();
        $lockbox = Lockbox::factory()->for($vault)->create();
        [$doomed, $kept] = Secret::factory()->for($lockbox)->count(2)->create()->all();

        $this->actingAs($user)->delete("/secrets/{$doomed->uuid}")->assertRedirect();

        expect($lockbox->secrets()->pluck('uuid')->all())->toBe([$kept->uuid]);
    });
});
