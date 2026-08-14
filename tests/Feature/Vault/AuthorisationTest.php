<?php

use App\Enums\VaultRole;
use App\Models\Lockbox;
use App\Models\Secret;
use App\Models\User;
use App\Models\Vault;
use App\Models\VaultMembership;
use Database\Factories\EnvelopeFixtures;
use Illuminate\Support\Str;

/**
 * @return array{user: User, vault: Vault, lockbox: Lockbox, secret: Secret}
 */
function vaultTree(?User $owner = null, VaultRole $role = VaultRole::Owner): array
{
    $user = $owner ?? User::factory()->create();
    $vault = Vault::factory()->for($user, 'owner')->withMember($user, $role)->create();
    $lockbox = Lockbox::factory()->for($vault)->create();
    $secret = Secret::factory()->for($lockbox)->create();

    return ['user' => $user, 'vault' => $vault, 'lockbox' => $lockbox, 'secret' => $secret];
}

/**
 * Every request another user could make against a resource they do not hold a
 * membership for.
 *
 * @return array<int, array{string, string}>
 */
function everyRoute(Vault $vault, Lockbox $lockbox, Secret $secret): array
{
    return [
        ['get', "/vaults/{$vault->uuid}"],
        ['patch', "/vaults/{$vault->uuid}"],
        ['delete', "/vaults/{$vault->uuid}"],
        ['post', "/vaults/{$vault->uuid}/lockboxes"],
        ['get', "/lockboxes/{$lockbox->uuid}"],
        ['patch', "/lockboxes/{$lockbox->uuid}"],
        ['delete', "/lockboxes/{$lockbox->uuid}"],
        ['post', "/lockboxes/{$lockbox->uuid}/secrets"],
        ['patch', "/secrets/{$secret->uuid}"],
        ['delete', "/secrets/{$secret->uuid}"],
    ];
}

describe('IDOR', function () {
    /*
     | 404, never 403.
     |
     | A 403 confirms the record exists, which turns every endpoint into an
     | existence oracle over identifiers the attacker should know nothing about.
     | Someone else's vault has to be indistinguishable from one that was never
     | there.
     */
    it('answers 404 on every one of another user\'s resources', function () {
        $tree = vaultTree();
        $stranger = User::factory()->create();

        $statuses = [];

        foreach (everyRoute($tree['vault'], $tree['lockbox'], $tree['secret']) as [$method, $url]) {
            $statuses["{$method} {$url}"] = $this->actingAs($stranger)->call(strtoupper($method), $url)->status();
        }

        // Compared as a map so a failure names the route that diverged.
        expect($statuses)->toBe(array_fill_keys(array_keys($statuses), 404));
    });

    it('answers 404 the same way for a uuid that does not exist at all', function () {
        $stranger = User::factory()->create();
        $missing = (string) Str::uuid7();

        $this->actingAs($stranger)->get("/vaults/{$missing}")->assertNotFound();
        $this->actingAs($stranger)->get("/lockboxes/{$missing}")->assertNotFound();
    });

    it('answers 404 once a membership is revoked', function () {
        $tree = vaultTree();
        $vault = $tree['vault'];

        $vault->memberships()->update(['revoked_at' => now()]);

        $this->actingAs($tree['user'])->get("/vaults/{$vault->uuid}")->assertNotFound();
    });

    /*
     | Soft-deleting a vault hides the vault but leaves its lockboxes and
     | secrets as live, routable rows for the length of the grace period. A UUID
     | captured before the delete must not still open afterwards.
     */
    it('answers 404 for children of a deleted vault', function () {
        $tree = vaultTree();
        $tree['vault']->delete();

        $this->actingAs($tree['user'])->get("/lockboxes/{$tree['lockbox']->uuid}")->assertNotFound();
        $this->actingAs($tree['user'])->delete("/secrets/{$tree['secret']->uuid}")->assertNotFound();
    });

    it('answers 404 for secrets of a deleted lockbox', function () {
        $tree = vaultTree();
        $tree['lockbox']->delete();

        $this->actingAs($tree['user'])->patch("/secrets/{$tree['secret']->uuid}")->assertNotFound();
    });

    it('requires authentication for every route', function () {
        $tree = vaultTree();

        foreach (everyRoute($tree['vault'], $tree['lockbox'], $tree['secret']) as [$method, $url]) {
            $this->call(strtoupper($method), $url)->assertRedirect('/login');
        }

    });
});

describe('roles', function () {
    /*
     | A viewer is blocked from every write path. Worth stating what this does
     | and does not achieve: it stops a viewer *changing* a vault. It cannot
     | stop them reading it — they hold the Vault Key, so they can decrypt
     | whatever they can fetch, and no server-side rule changes that.
     */
    it('lets a viewer read and blocks every write', function () {
        $tree = vaultTree(role: VaultRole::Viewer);

        $this->actingAs($tree['user'])->get("/vaults/{$tree['vault']->uuid}")->assertOk();
        $this->actingAs($tree['user'])->get("/lockboxes/{$tree['lockbox']->uuid}")->assertOk();

        $statuses = [];

        foreach ([
            ['patch', "/vaults/{$tree['vault']->uuid}"],
            ['post', "/vaults/{$tree['vault']->uuid}/lockboxes"],
            ['patch', "/lockboxes/{$tree['lockbox']->uuid}"],
            ['delete', "/lockboxes/{$tree['lockbox']->uuid}"],
            ['post', "/lockboxes/{$tree['lockbox']->uuid}/secrets"],
            ['patch', "/secrets/{$tree['secret']->uuid}"],
            ['delete', "/secrets/{$tree['secret']->uuid}"],
        ] as [$method, $url]) {
            $statuses["{$method} {$url}"] = $this->actingAs($tree['user'])->call(strtoupper($method), $url)->status();
        }

        expect($statuses)->toBe(array_fill_keys(array_keys($statuses), 404));
    });

    it('lets an editor write but not delete the vault', function () {
        $tree = vaultTree(role: VaultRole::Editor);

        $this->actingAs($tree['user'])
            ->post("/vaults/{$tree['vault']->uuid}/lockboxes", [
                'uuid' => (string) Str::uuid7(),
                'payload_ct' => EnvelopeFixtures::envelope(96),
                'wrapped_item_key' => EnvelopeFixtures::envelope(48),
                'payload_version' => 1,
            ])
            ->assertRedirect();

        $this->actingAs($tree['user'])->delete("/vaults/{$tree['vault']->uuid}")->assertNotFound();
    });

    it('lets a member of one vault do nothing in another', function () {
        $tree = vaultTree();

        // A genuine member — of a different vault. Membership is per-vault, and
        // holding one must never imply holding another.
        $neighbour = User::factory()->create();
        VaultMembership::factory()->for($neighbour)->create();

        $this->actingAs($neighbour)->get("/vaults/{$tree['vault']->uuid}")->assertNotFound();
    });
});
