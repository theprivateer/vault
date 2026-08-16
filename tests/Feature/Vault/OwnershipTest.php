<?php

use App\Enums\AuditAction;
use App\Enums\VaultRole;
use App\Models\AuditEvent;
use App\Models\User;
use App\Models\Vault;
use App\Models\VaultMembership;
use Database\Factories\EnvelopeFixtures;
use Illuminate\Support\Str;
use Inertia\Testing\AssertableInertia;

/**
 * Handing a vault over, and the deletion it makes possible.
 *
 * The two are one problem seen from either end. A vault with other members has
 * to have somewhere to go before its owner can leave it, or those members are
 * left holding a Vault Key that wraps rows nobody can reach — access withdrawn
 * by a route that never mentions access.
 *
 * What is *not* tested here, because it is not true: that transfer takes
 * anything away from the outgoing owner. It does not, and cannot. They keep the
 * sealed Vault Key on their membership row and can read everything in the vault
 * until somebody revokes them and rotates. The tests assert that their row
 * survives, which is the same fact stated as a property.
 */

/** A member who has confirmed the owner's fingerprint, which transfer requires. */
function acceptedMember(Vault $vault, VaultRole $role = VaultRole::Editor): User
{
    $user = User::factory()->create();

    $vault->memberships()->create([
        'uuid' => (string) Str::uuid7(),
        'user_id' => $user->getKey(),
        'role' => $role,
        'wrapped_vault_key' => EnvelopeFixtures::sealedEnvelope(),
        'key_epoch' => $vault->key_epoch,
        'granted_by' => $vault->owner_id,
        'accepted_at' => now(),
    ]);

    return $user;
}

/**
 * A membership row, revoked or not.
 *
 * Deliberately not `Vault::membershipFor`, which excludes revoked rows — several
 * of these tests are about what happens to a row *after* it stops granting
 * access, and a helper that hid those would make the assertions vacuous.
 */
function membershipOf(Vault $vault, User $user): VaultMembership
{
    return VaultMembership::query()
        ->where('vault_id', $vault->getKey())
        ->where('user_id', $user->getKey())
        ->sole();
}

function roleOf(Vault $vault, User $user): VaultRole
{
    return membershipOf($vault, $user)->role;
}

describe('handing a vault over', function () {
    it('moves the owner role, the owner column and the outgoing owner to editor', function () {
        $owner = User::factory()->create();
        $vault = Vault::factory()->ownedBy($owner)->create();
        $successor = acceptedMember($vault);

        $this->actingAs($owner)
            ->patch("/vaults/{$vault->uuid}/owner", ['user_uuid' => $successor->uuid])
            ->assertRedirect("/vaults/{$vault->uuid}");

        expect($vault->refresh()->owner_id)->toBe($successor->getKey())
            ->and(roleOf($vault, $successor))->toBe(VaultRole::Owner)
            ->and(roleOf($vault, $owner))->toBe(VaultRole::Editor);
    });

    /*
     | The property that makes transfer cheap, and the one the interface must not
     | oversell. Nothing is re-encrypted because the recipient has held a sealed
     | copy of the Vault Key since they were granted access — so a transfer that
     | touched a ciphertext or advanced the epoch would be doing something the
     | design does not call for.
     */
    it('re-encrypts nothing and leaves the key epoch alone', function () {
        $owner = User::factory()->create();
        $vault = Vault::factory()->ownedBy($owner)->create();
        $successor = acceptedMember($vault);

        $before = [
            'vault' => $vault->payload_ct->base64,
            'item' => $vault->wrapped_item_key->base64,
            'epoch' => $vault->key_epoch,
            'ownerKey' => membershipOf($vault, $owner)->wrapped_vault_key->base64,
            'successorKey' => membershipOf($vault, $successor)->wrapped_vault_key->base64,
        ];

        $this->actingAs($owner)->patch("/vaults/{$vault->uuid}/owner", ['user_uuid' => $successor->uuid]);

        $after = $vault->refresh();

        expect($after->payload_ct->base64)->toBe($before['vault'])
            ->and($after->wrapped_item_key->base64)->toBe($before['item'])
            ->and($after->key_epoch)->toBe($before['epoch'])
            ->and($after->rekey_required_at)->toBeNull()
            ->and(membershipOf($after, $owner)->wrapped_vault_key->base64)->toBe($before['ownerKey'])
            ->and(membershipOf($after, $successor)->wrapped_vault_key->base64)
            ->toBe($before['successorKey']);
    });

    /*
     | Demoted, never revoked. Revoking would remove the row that holds the
     | outgoing owner's sealed Vault Key, and they were using this vault a moment
     | ago — leaving is a separate decision. What transfer *does* change is that
     | the decision becomes available to somebody: an administrator cannot be
     | revoked, so before this the old owner was immovable.
     */
    it('leaves the outgoing owner a live membership the new owner can now revoke', function () {
        $owner = User::factory()->create();
        $vault = Vault::factory()->ownedBy($owner)->create();
        $successor = acceptedMember($vault);

        $this->actingAs($owner)->patch("/vaults/{$vault->uuid}/owner", ['user_uuid' => $successor->uuid]);

        $demoted = membershipOf($vault, $owner);

        expect($demoted->revoked_at)->toBeNull();

        $this->actingAs($successor)->delete("/memberships/{$demoted->uuid}")->assertRedirect();

        expect($demoted->refresh()->revoked_at)->not->toBeNull();
    });

    it('records the transfer against the recipient’s membership', function () {
        $owner = User::factory()->create();
        $vault = Vault::factory()->ownedBy($owner)->create();
        $successor = acceptedMember($vault, VaultRole::Viewer);

        $this->actingAs($owner)->patch("/vaults/{$vault->uuid}/owner", ['user_uuid' => $successor->uuid]);

        $event = AuditEvent::query()
            ->where('action', AuditAction::VaultOwnershipTransferred)
            ->sole();

        expect($event->subject_type)->toBe('membership')
            ->and($event->subject_uuid)->toBe(membershipOf($vault, $successor)->uuid)
            ->and($event->actor_uuid)->toBe($owner->uuid)
            ->and($event->metadata)->toBe('{"previous_role":"viewer","role":"owner"}');
    });

    it('shows up in the vault’s activity feed', function () {
        $owner = User::factory()->create();
        $vault = Vault::factory()->ownedBy($owner)->create();
        $successor = acceptedMember($vault);

        $this->actingAs($owner)->patch("/vaults/{$vault->uuid}/owner", ['user_uuid' => $successor->uuid]);

        $this->actingAs($successor)
            ->get("/vaults/{$vault->uuid}/activity")
            ->assertInertia(fn (AssertableInertia $page) => $page->where(
                'events.0.action',
                AuditAction::VaultOwnershipTransferred->value,
            ));
    });
});

describe('who may receive a vault, and who may give one', function () {
    /*
     | Ownership without a sealed Vault Key is a title over something you cannot
     | open. The fix is named in the message rather than the fault, because the
     | actor is an administrator who can already see who is in the vault.
     */
    it('refuses somebody who is not a member', function () {
        $owner = User::factory()->create();
        $vault = Vault::factory()->ownedBy($owner)->create();
        $stranger = User::factory()->create();

        $this->actingAs($owner)
            ->patch("/vaults/{$vault->uuid}/owner", ['user_uuid' => $stranger->uuid])
            ->assertSessionHasErrors('user_uuid');

        expect($vault->refresh()->owner_id)->toBe($owner->getKey());
    });

    it('refuses somebody whose membership was revoked', function () {
        $owner = User::factory()->create();
        $vault = Vault::factory()->ownedBy($owner)->create();
        $former = acceptedMember($vault);

        membershipOf($vault, $former)->forceFill(['revoked_at' => now()])->save();

        $this->actingAs($owner)
            ->patch("/vaults/{$vault->uuid}/owner", ['user_uuid' => $former->uuid])
            ->assertSessionHasErrors('user_uuid');

        expect($vault->refresh()->owner_id)->toBe($owner->getKey());
    });

    /*
     | A membership stranded on an old epoch holds a key that unwraps nothing. An
     | owner in that state could not rotate the vault back out of it, so there
     | would be no way to recover.
     */
    it('refuses somebody stranded on an old key epoch', function () {
        $owner = User::factory()->create();
        $vault = Vault::factory()->ownedBy($owner)->create();
        $successor = acceptedMember($vault);

        membershipOf($vault, $successor)->forceFill(['key_epoch' => $vault->key_epoch - 1])->save();

        $this->actingAs($owner)
            ->patch("/vaults/{$vault->uuid}/owner", ['user_uuid' => $successor->uuid])
            ->assertSessionHasErrors('user_uuid');

        expect(roleOf($vault, $successor))->toBe(VaultRole::Editor);
    });

    /*
     | Accepting is the recipient saying they compared the granter's fingerprint
     | out of band. Administration is the last thing to hand to an account that
     | has not yet said it trusts you — and it is also the only evidence
     | available here that their client engaged with the grant at all.
     */
    it('refuses a member who has not confirmed the fingerprint', function () {
        $owner = User::factory()->create();
        $vault = Vault::factory()->ownedBy($owner)->create();
        $member = User::factory()->create();

        $vault->memberships()->create([
            'uuid' => (string) Str::uuid7(),
            'user_id' => $member->getKey(),
            'role' => VaultRole::Editor,
            'wrapped_vault_key' => EnvelopeFixtures::sealedEnvelope(),
            'key_epoch' => $vault->key_epoch,
            'granted_by' => $owner->getKey(),
        ]);

        $this->actingAs($owner)
            ->patch("/vaults/{$vault->uuid}/owner", ['user_uuid' => $member->uuid])
            ->assertSessionHasErrors('user_uuid');

        expect(roleOf($vault, $member))->toBe(VaultRole::Editor);
    });

    it('refuses transferring to yourself', function () {
        $owner = User::factory()->create();
        $vault = Vault::factory()->ownedBy($owner)->create();

        $this->actingAs($owner)
            ->patch("/vaults/{$vault->uuid}/owner", ['user_uuid' => $owner->uuid])
            ->assertSessionHasErrors('user_uuid');
    });

    /*
     | 404 rather than 403, as everywhere: an editor asking about a vault they
     | cannot administer must not be able to distinguish "you may not" from
     | "there is no such vault".
     */
    it('is not an editor’s to give, and answers 404', function () {
        $owner = User::factory()->create();
        $vault = Vault::factory()->ownedBy($owner)->create();
        $editor = acceptedMember($vault);
        $other = acceptedMember($vault);

        $this->actingAs($editor)
            ->patch("/vaults/{$vault->uuid}/owner", ['user_uuid' => $other->uuid])
            ->assertNotFound();

        expect($vault->refresh()->owner_id)->toBe($owner->getKey());
    });

    it('is not a stranger’s to give, and answers 404', function () {
        $owner = User::factory()->create();
        $vault = Vault::factory()->ownedBy($owner)->create();
        $successor = acceptedMember($vault);

        $this->actingAs(User::factory()->create())
            ->patch("/vaults/{$vault->uuid}/owner", ['user_uuid' => $successor->uuid])
            ->assertNotFound();
    });
});

describe('deleting a shared vault', function () {
    /*
     | The guard this phase existed to add. Their access *is* a sealed copy of
     | the Vault Key on a membership row, so deleting the vault under them is a
     | revocation performed by a route that never mentions revocation, and
     | without the audit trail one would have left.
     */
    it('is refused while somebody else still holds a key', function () {
        $owner = User::factory()->create();
        $vault = Vault::factory()->ownedBy($owner)->create();
        acceptedMember($vault);

        $this->actingAs($owner)
            ->delete("/vaults/{$vault->uuid}")
            ->assertSessionHasErrors('vault');

        expect($vault->refresh()->trashed())->toBeFalse();
    });

    it('is allowed once the vault is yours alone', function () {
        $owner = User::factory()->create();
        $vault = Vault::factory()->ownedBy($owner)->create();

        $this->actingAs($owner)->delete("/vaults/{$vault->uuid}")->assertRedirect('/vaults');

        expect($vault->refresh()->trashed())->toBeTrue();
    });

    /*
     | A revoked member's access was already cut, and the re-key that revocation
     | demanded means their cached key opens nothing written since. Counting them
     | would leave a vault permanently undeletable by anyone who had ever shared
     | it — a guard that never releases is a bug wearing a safety jacket.
     */
    it('does not count somebody who has been revoked', function () {
        $owner = User::factory()->create();
        $vault = Vault::factory()->ownedBy($owner)->create();
        $former = acceptedMember($vault);

        membershipOf($vault, $former)->forceFill(['revoked_at' => now()])->save();

        $this->actingAs($owner)->delete("/vaults/{$vault->uuid}")->assertRedirect('/vaults');

        expect($vault->refresh()->trashed())->toBeTrue();
    });

    it('lets the new owner delete a vault the old one handed over and then left', function () {
        $owner = User::factory()->create();
        $vault = Vault::factory()->ownedBy($owner)->create();
        $successor = acceptedMember($vault);

        $this->actingAs($owner)->patch("/vaults/{$vault->uuid}/owner", ['user_uuid' => $successor->uuid]);

        $demoted = membershipOf($vault, $owner);
        $this->actingAs($successor)->delete("/memberships/{$demoted->uuid}");

        $this->actingAs($successor)->delete("/vaults/{$vault->uuid}")->assertRedirect('/vaults');

        expect($vault->refresh()->trashed())->toBeTrue();
    });

    it('is still not an editor’s to do, and answers 404', function () {
        $owner = User::factory()->create();
        $vault = Vault::factory()->ownedBy($owner)->create();
        $editor = acceptedMember($vault);

        $this->actingAs($editor)->delete("/vaults/{$vault->uuid}")->assertNotFound();

        expect($vault->refresh()->trashed())->toBeFalse();
    });
});
