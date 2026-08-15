<?php

use App\Enums\VaultRole;
use App\Models\Lockbox;
use App\Models\Secret;
use App\Models\User;
use App\Models\Vault;
use App\Models\VaultMembership;
use Database\Factories\EnvelopeFixtures;
use Illuminate\Support\Str;
use Tests\TestCase;

/**
 * Every role against every action, exhaustively.
 *
 * The kind of test that is skipped and then regretted. Role checks are the one
 * part of this system with no cryptographic backstop — a viewer holds the Vault
 * Key like everyone else, so the *only* thing stopping them writing is a server
 * saying no — and a permission that quietly widened would leave no trace
 * anywhere else. A table with a row per pair is boring and it is the point.
 *
 * Read the expectations as: 302 means the write was accepted (Inertia redirects
 * on success), 200 means a page rendered, 404 means refused. There is no 403
 * anywhere in this file, and its absence is deliberate — see
 * .ai/rules/policies.md.
 */

/**
 * The whole tree, plus a member at the role under test.
 *
 * @return array{actor: User, owner: User, vault: Vault, lockbox: Lockbox, secret: Secret, membership: VaultMembership}
 */
function roleFixture(?VaultRole $role): array
{
    $owner = User::factory()->create();
    $actor = $role === VaultRole::Owner ? $owner : User::factory()->create();

    $vault = Vault::factory()->ownedBy($owner)->create();

    if ($role !== null && $role !== VaultRole::Owner) {
        $vault->memberships()->create([
            'uuid' => (string) Str::uuid7(),
            'user_id' => $actor->getKey(),
            'role' => $role,
            'wrapped_vault_key' => EnvelopeFixtures::sealedEnvelope(),
            'key_epoch' => $vault->key_epoch,
            'granted_by' => $owner->getKey(),
        ]);
    }

    $lockbox = Lockbox::factory()->for($vault)->create();
    $secret = Secret::factory()->for($lockbox)->create();

    // A second member, so revoke has something to act on that is not the owner.
    $membership = $vault->memberships()->create([
        'uuid' => (string) Str::uuid7(),
        'user_id' => User::factory()->create()->getKey(),
        'role' => VaultRole::Viewer,
        'wrapped_vault_key' => EnvelopeFixtures::sealedEnvelope(),
        'key_epoch' => $vault->key_epoch,
        'granted_by' => $owner->getKey(),
    ]);

    return compact('actor', 'owner', 'vault', 'lockbox', 'secret', 'membership');
}

/**
 * @param  array{actor: User, owner: User, vault: Vault, lockbox: Lockbox, secret: Secret, membership: VaultMembership}  $fixture
 * @return array<string, array{string, string, array<string, mixed>}>
 */
function everyAction(array $fixture): array
{
    ['vault' => $vault, 'lockbox' => $lockbox, 'secret' => $secret, 'membership' => $membership] = $fixture;

    return [
        'view vault' => ['get', "/vaults/{$vault->uuid}", []],
        'update vault' => ['patch', "/vaults/{$vault->uuid}", itemPayload()],
        'delete vault' => ['delete', "/vaults/{$vault->uuid}", []],
        'create lockbox' => ['post', "/vaults/{$vault->uuid}/lockboxes", itemPayload(['sort_order' => 1])],
        'view lockbox' => ['get', "/lockboxes/{$lockbox->uuid}", []],
        'update lockbox' => ['patch', "/lockboxes/{$lockbox->uuid}", itemPayload()],
        'delete lockbox' => ['delete', "/lockboxes/{$lockbox->uuid}", []],
        'create secret' => ['post', "/lockboxes/{$lockbox->uuid}/secrets", itemPayload(['sort_order' => 1])],
        'update secret' => [
            'patch',
            "/secrets/{$secret->uuid}",
            [...itemPayload(['payload_version' => 2]), 'expected_version' => $secret->current_version],
        ],
        'delete secret' => ['delete', "/secrets/{$secret->uuid}", []],
        'open re-key' => ['get', "/vaults/{$vault->uuid}/rekey", []],
        'revoke a member' => ['delete', "/memberships/{$membership->uuid}", []],
    ];
}

/**
 * The whole matrix in one place.
 *
 * @return array<string, array<string, int>>
 */
function expectedStatuses(): array
{
    // A read renders a page (200); a write redirects (302); a refusal is 404.
    $owner = [
        'view vault' => 200,
        'update vault' => 302,
        'delete vault' => 302,
        'create lockbox' => 302,
        'view lockbox' => 200,
        'update lockbox' => 302,
        'delete lockbox' => 302,
        'create secret' => 302,
        'update secret' => 302,
        'delete secret' => 302,
        'open re-key' => 200,
        'revoke a member' => 302,
    ];

    $editor = [
        ...$owner,
        // Administration, not authorship: an editor changes contents, not who
        // can read them, and not the key everything hangs from.
        'delete vault' => 404,
        'open re-key' => 404,
        'revoke a member' => 404,
    ];

    $refused = array_map(fn (): int => 404, $owner);

    return [
        'owner' => $owner,
        'editor' => $editor,
        // Reads and nothing else.
        'viewer' => [...$refused, 'view vault' => 200, 'view lockbox' => 200],
        // No membership at all, and a revoked one, must be indistinguishable
        // from a vault that never existed.
        'stranger' => $refused,
        'revoked' => $refused,
    ];
}

/**
 * Runs every action, each against its own freshly built vault.
 *
 * Rebuilt per action rather than reused, because the actions are not
 * independent when they share one: `delete vault` succeeds and soft-deletes it,
 * after which everything below answers 404 — which reads exactly like a
 * permission failure and would have hidden the rest of the row. Found the first
 * time this test ran.
 *
 * @param  (callable(array{actor: User, owner: User, vault: Vault, lockbox: Lockbox, secret: Secret, membership: VaultMembership}): void)|null  $mutate
 * @return array<string, int>
 */
function statusesFor(TestCase $test, ?VaultRole $role, ?callable $mutate = null): array
{
    $statuses = [];

    foreach (array_keys(everyAction(roleFixture($role))) as $name) {
        $fixture = roleFixture($role);

        if ($mutate !== null) {
            $mutate($fixture);
        }

        [$method, $url, $payload] = everyAction($fixture)[$name];

        $statuses[$name] = $test->actingAs($fixture['actor'])
            ->call(strtoupper($method), $url, $payload)
            ->status();
    }

    return $statuses;
}

it('gives an owner every ability', function () {
    expect(statusesFor($this, VaultRole::Owner))->toBe(expectedStatuses()['owner']);
});

it('lets an editor write content but not change membership or keys', function () {
    expect(statusesFor($this, VaultRole::Editor))->toBe(expectedStatuses()['editor']);
});

/**
 * The row that matters most, and the one with the honest caveat attached: this
 * proves a viewer cannot *write*. It does not and cannot prove they cannot read
 * and copy — they hold the Vault Key, so they can decrypt whatever they fetch.
 * See docs/01 § A note on what "read-only" means.
 */
it('blocks a viewer from every write path', function () {
    expect(statusesFor($this, VaultRole::Viewer))->toBe(expectedStatuses()['viewer']);
});

it('treats someone with no membership as though the vault did not exist', function () {
    expect(statusesFor($this, null))->toBe(expectedStatuses()['stranger']);
});

/**
 * Revocation is enforced on read, immediately — before any re-key has happened.
 * That part is instant and enforceable; the rotation is neither, which is why
 * the two are separated. If this row ever went green for anything, removing
 * somebody would mean nothing until an owner happened to log in.
 */
it('treats a revoked member as though they had never been one', function () {
    $revoke = function (array $fixture): void {
        $vault = $fixture['vault'];
        $actor = $fixture['actor'];

        if ($vault instanceof Vault && $actor instanceof User) {
            $vault->memberships()->where('user_id', $actor->getKey())->update(['revoked_at' => now()]);
        }
    };

    expect(statusesFor($this, VaultRole::Editor, $revoke))->toBe(expectedStatuses()['revoked']);
});

describe('accepting a grant', function () {
    it('is the recipient\'s to do, and nobody else\'s', function () {
        $fixture = roleFixture(VaultRole::Owner);
        $membership = $fixture['membership'];

        // The owner granted it; they cannot accept on the recipient's behalf,
        // because accepting means "I compared their fingerprint".
        $this->actingAs($fixture['owner'])
            ->patch("/memberships/{$membership->uuid}")
            ->assertNotFound();

        $this->actingAs($membership->user)
            ->patch("/memberships/{$membership->uuid}")
            ->assertRedirect();

        expect($membership->refresh()->accepted_at)->not->toBeNull();
    });

    it('cannot revive a revoked membership', function () {
        $fixture = roleFixture(VaultRole::Owner);
        $membership = $fixture['membership'];

        $membership->forceFill(['revoked_at' => now()])->save();

        $this->actingAs($membership->user)
            ->patch("/memberships/{$membership->uuid}")
            ->assertNotFound();

        expect($membership->refresh()->accepted_at)->toBeNull();
    });
});

/**
 * The Vault Key exists only as the sealed copies on membership rows. Revoking
 * the last administrator's row would destroy the vault's contents with no way
 * back, so the policy refuses rather than trusting the interface not to offer
 * it.
 */
it('refuses to revoke an owner, which would strand the vault', function () {
    $owner = User::factory()->create();
    $vault = Vault::factory()->ownedBy($owner)->create();
    $membership = $vault->memberships()->sole();

    $this->actingAs($owner)
        ->delete("/memberships/{$membership->uuid}")
        ->assertNotFound();

    expect($membership->refresh()->revoked_at)->toBeNull();
});
