<?php

use App\Enums\AuditAction;
use App\Enums\VaultRole;
use App\Models\AuditEvent;
use App\Models\Lockbox;
use App\Models\Secret;
use App\Models\User;
use App\Models\Vault;
use App\Models\VaultFile;
use App\Models\VaultMembership;
use Inertia\Testing\AssertableInertia;

/**
 * The bulk read behind the export page (Phase 12, task 3).
 *
 * The interesting property is the one that is easiest to lose in a query this
 * wide: it must hand over everything the caller holds a key to and not one row
 * more. The vault pages enforce that with a policy per route; this endpoint has
 * no route parameter to attach a policy to, so the authorisation lives in the
 * shape of the query — it starts at membership rows — and these tests are what
 * hold it there.
 */
function memberOf(Vault $vault, User $user, VaultRole $role = VaultRole::Editor): VaultMembership
{
    return VaultMembership::factory()->for($vault)->for($user)->role($role)->create();
}

describe('what the bundle contains', function () {
    it('hands over every vault the caller is a live member of', function () {
        $user = User::factory()->create();
        $own = Vault::factory()->ownedBy($user)->create();
        $shared = Vault::factory()->create();
        memberOf($shared, $user, VaultRole::Viewer);

        $response = $this->actingAs($user)->getJson('/account/export/data');

        expect(collect(jsonArray($response, 'vaults'))->pluck('vault.uuid')->sort()->values()->all())
            ->toEqual(collect([$own->uuid, $shared->uuid])->sort()->values()->all());
    });

    it('includes the lockboxes, secrets and files of each one', function () {
        $user = User::factory()->create();
        $vault = Vault::factory()->ownedBy($user)->create();
        $lockbox = Lockbox::factory()->for($vault)->create();
        Secret::factory()->for($lockbox)->count(3)->create();
        VaultFile::factory()->for($lockbox)->create();

        $entry = jsonArray($this->actingAs($user)->getJson('/account/export/data'), 'vaults.0');

        expect($entry['lockboxes'])->toHaveCount(1)
            ->and($entry['secrets'])->toHaveCount(3)
            ->and($entry['files'])->toHaveCount(1);
    });

    it('carries the wrapped keys, since nothing is readable without them', function () {
        $user = User::factory()->create();
        $vault = Vault::factory()->ownedBy($user)->create();
        Secret::factory()->for(Lockbox::factory()->for($vault))->create();

        $response = $this->actingAs($user)->getJson('/account/export/data');

        expect(jsonString($response, 'vaults.0.vault.membership.wrappedVaultKey'))->not->toBeEmpty()
            ->and(jsonString($response, 'vaults.0.vault.wrappedItemKey'))->not->toBeEmpty()
            ->and(jsonString($response, 'vaults.0.secrets.0.wrappedItemKey'))->not->toBeEmpty();
    });

    it('names the account, so a file says whose it is', function () {
        $user = User::factory()->create();

        $this->actingAs($user)->getJson('/account/export/data')->assertJsonPath('handle', $user->handle);
    });
});

describe('what the bundle must not contain', function () {
    /*
     | The whole authorisation model of this endpoint. There is no route
     | parameter and therefore no `can:` middleware — the query starts at the
     | caller's membership rows, so a vault they have no row for cannot appear.
     */
    it('never includes a vault the caller has no membership of', function () {
        $user = User::factory()->create();
        $stranger = Vault::factory()->create();
        Secret::factory()->for(Lockbox::factory()->for($stranger))->create();

        $response = $this->actingAs($user)->getJson('/account/export/data');

        expect(jsonArray($response, 'vaults'))->toBeEmpty();
    });

    it('excludes a vault whose membership was revoked', function () {
        $user = User::factory()->create();
        $vault = Vault::factory()->create();
        VaultMembership::factory()->for($vault)->for($user)->revoked()->create();

        expect(jsonArray($this->actingAs($user)->getJson('/account/export/data'), 'vaults'))->toBeEmpty();
    });

    it('excludes a vault inside its deletion grace period', function () {
        $user = User::factory()->create();
        Vault::factory()->ownedBy($user)->create()->delete();

        expect(jsonArray($this->actingAs($user)->getJson('/account/export/data'), 'vaults'))->toBeEmpty();
    });

    /*
     | A trashed secret is restorable for 30 days on this server, and that grace
     | period is a property of the server rather than of a file on a USB stick.
     | An archive that quietly reintroduced deleted credentials would be a
     | surprise in the wrong direction.
     */
    it('excludes trashed lockboxes and secrets', function () {
        $user = User::factory()->create();
        $vault = Vault::factory()->ownedBy($user)->create();
        $lockbox = Lockbox::factory()->for($vault)->create();

        Secret::factory()->for($lockbox)->create();
        Secret::factory()->for($lockbox)->create()->delete();
        Lockbox::factory()->for($vault)->create()->delete();

        $entry = jsonArray($this->actingAs($user)->getJson('/account/export/data'), 'vaults.0');

        expect($entry['lockboxes'])->toHaveCount(1)
            ->and($entry['secrets'])->toHaveCount(1);
    });

    it('refuses anybody who is not signed in', function () {
        $this->getJson('/account/export/data')->assertUnauthorized();
    });
});

describe('the audit entry', function () {
    /*
     | The widest read the application allows, and therefore the one an operator
     | should be able to find without knowing to look for it.
     */
    it('records the export against the user, with what was handed over', function () {
        $user = User::factory()->create();
        $vault = Vault::factory()->ownedBy($user)->create();
        Secret::factory()->for(Lockbox::factory()->for($vault))->count(2)->create();

        $this->actingAs($user)->getJson('/account/export/data')->assertOk();

        $event = AuditEvent::query()->where('action', AuditAction::AccountExported)->sole();

        expect($event->actor_uuid)->toBe($user->uuid)
            ->and($event->decodedMetadata())->toMatchArray(['vault_count' => 1, 'secret_count' => 2, 'file_count' => 0]);
    });

    it('records an export that returned nothing, because an attempt is the event', function () {
        $user = User::factory()->create();

        $this->actingAs($user)->getJson('/account/export/data')->assertOk();

        expect(AuditEvent::query()->where('action', AuditAction::AccountExported)->count())->toBe(1);
    });
});

describe('the page', function () {
    it('renders for a signed-in user', function () {
        $this->actingAs(User::factory()->create())->get('/account/export')->assertOk();
    });

    it('sends no vault data of its own — the page fetches ciphertext itself', function () {
        $user = User::factory()->create();
        Vault::factory()->ownedBy($user)->create();

        // The page carries nothing but the shared props. An export is a
        // deliberate act, and a page that shipped the whole account in its
        // props would perform one on every visit.
        $this->actingAs($user)
            ->get('/account/export')
            ->assertInertia(fn (AssertableInertia $page) => $page
                ->component('account/Export')
                ->missing('vaults'));
    });
});
