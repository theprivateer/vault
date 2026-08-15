<?php

use App\Enums\AuditAction;
use App\Enums\VaultRole;
use App\Models\AuditEvent;
use App\Models\Lockbox;
use App\Models\Secret;
use App\Models\SecretVersion;
use App\Models\User;
use App\Models\Vault;
use Database\Factories\EnvelopeFixtures;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Str;
use Inertia\Testing\AssertableInertia;

/**
 * Version history: what an edit keeps, and what nothing can do to it afterwards.
 *
 * The feature is ordinary — old payloads, a diff, a restore — and the thing
 * worth testing is the property that made it non-obvious to build. **An
 * archived version is a fresh encryption bound to its own identity, not a copy
 * of the column it replaced.** A copy would carry the live payload's associated
 * data, which means any archived version could be written back over the live
 * row and would verify: a silent rollback to a password that was rotated
 * because it leaked. The server cannot make that copy even if a future change
 * wanted it to, because it has never held a key — but it can be handed one by a
 * client, so the archive is required on the write path and the tests below hold
 * that requirement in place.
 *
 * The other half is retention. History is useful and history is a liability,
 * and the tests cover both halves of the answer: a policy that bounds it, and a
 * purge that ends it now with no grace period, because a grace period on
 * "erase the leaked password" defeats the purpose.
 */

/**
 * A vault, a lockbox and one secret already at version 1.
 *
 * @return array{owner: User, vault: Vault, lockbox: Lockbox, secret: Secret}
 */
function historyFixture(): array
{
    $owner = User::factory()->create();
    $vault = Vault::factory()->ownedBy($owner)->create();
    $lockbox = Lockbox::factory()->for($vault)->create();
    $secret = Secret::factory()->for($lockbox)->create();

    return compact('owner', 'vault', 'lockbox', 'secret');
}

/**
 * One edit, carrying both the replacement and the payload it replaces.
 *
 * @param  array<string, mixed>  $overrides
 * @return array<string, mixed>
 */
function editPayload(Secret $secret, array $overrides = []): array
{
    return [
        'payload_ct' => EnvelopeFixtures::envelope(96),
        'wrapped_item_key' => EnvelopeFixtures::envelope(48),
        'payload_version' => 2,
        'version_uuid' => (string) Str::uuid7(),
        'version_payload_ct' => EnvelopeFixtures::envelope(96),
        'version_wrapped_item_key' => EnvelopeFixtures::envelope(48),
        'version_payload_version' => 2,
        'expected_version' => $secret->current_version,
        ...$overrides,
    ];
}

describe('an edit appends rather than overwrites', function () {
    it('keeps the payload it replaced, at the version that payload was live at', function () {
        ['owner' => $owner, 'secret' => $secret] = historyFixture();

        $payload = editPayload($secret);

        $this->actingAs($owner)->patch("/secrets/{$secret->uuid}", $payload)->assertRedirect();

        $version = $secret->versions()->sole();

        expect($version->version)->toBe(1)
            ->and($version->uuid)->toBe(payloadString($payload, 'version_uuid'))
            ->and($version->created_by)->toBe($owner->getKey())
            ->and($secret->refresh()->current_version)->toBe(2);
    });

    /*
     | The property the whole design turns on. The archived ciphertext is what
     | the browser sealed under `secret.version.payload`, not the bytes that
     | were in `secrets.payload_ct` a moment ago — those carry associated data
     | binding them to the live column, and storing them here would make every
     | version interchangeable with the present.
     */
    it('stores the separately sealed archive, never a copy of the live column', function () {
        ['owner' => $owner, 'secret' => $secret] = historyFixture();

        $wasLive = $secret->payload_ct->base64;
        $payload = editPayload($secret);

        $this->actingAs($owner)->patch("/secrets/{$secret->uuid}", $payload);

        $version = $secret->versions()->sole();

        expect($version->payload_ct->base64)
            ->toBe(payloadString($payload, 'version_payload_ct'))
            ->not->toBe($wasLive)
            ->and($version->wrapped_item_key->base64)
            ->toBe(payloadString($payload, 'version_wrapped_item_key'));
    });

    it('refuses an update that does not carry the payload it is replacing', function () {
        ['owner' => $owner, 'secret' => $secret] = historyFixture();

        $payload = editPayload($secret);
        unset($payload['version_payload_ct']);

        $this->actingAs($owner)
            ->patch("/secrets/{$secret->uuid}", $payload)
            ->assertSessionHasErrors('version_payload_ct');

        expect($secret->versions()->count())->toBe(0)
            ->and($secret->refresh()->current_version)->toBe(1);
    });

    /*
     | The archive is written inside the transaction that guards the update, so
     | a write that loses the concurrency race leaves nothing behind. Without
     | that, the loser's browser would have contributed a version to a history
     | whose corresponding edit never happened.
     */
    it('leaves no archive behind when the edit loses a concurrent write', function () {
        ['owner' => $owner, 'secret' => $secret] = historyFixture();

        $first = editPayload($secret);
        $second = editPayload($secret);

        $this->actingAs($owner)->patch("/secrets/{$secret->uuid}", $first)->assertRedirect();

        $this->actingAs($owner)
            ->patch("/secrets/{$secret->uuid}", $second)
            ->assertSessionHasErrors('expected_version');

        expect($secret->versions()->count())->toBe(1)
            ->and($secret->versions()->sole()->uuid)->toBe(payloadString($first, 'version_uuid'));
    });

    it('refuses to let a stored version be edited', function () {
        ['owner' => $owner, 'secret' => $secret] = historyFixture();

        $this->actingAs($owner)->patch("/secrets/{$secret->uuid}", editPayload($secret));

        $version = $secret->versions()->sole();

        expect(fn () => $version->update(['payload_version' => 1]))
            ->toThrow(RuntimeException::class, 'record of what a payload used to be');
    });

    it('takes a secret’s history with it when the secret is hard-deleted', function () {
        ['secret' => $secret] = historyFixture();

        SecretVersion::factory()->for($secret)->create();

        $secret->forceDelete();

        expect(SecretVersion::query()->count())->toBe(0);
    });
});

describe('reading and restoring', function () {
    it('renders the history page with every version still encrypted', function () {
        ['owner' => $owner, 'secret' => $secret] = historyFixture();

        $this->actingAs($owner)->patch("/secrets/{$secret->uuid}", editPayload($secret));

        $this->actingAs($owner)
            ->get("/secrets/{$secret->uuid}/history")
            ->assertInertia(fn (AssertableInertia $page) => $page
                ->component('secrets/History')
                ->has('versions', 1)
                ->has('versions.0.payloadCt')
                ->has('versions.0.wrappedItemKey')
                ->where('versions.0.version', 1)
                ->where('versions.0.author', $owner->display_name)
            );
    });

    /*
     | A restore is an ordinary edit carrying an old payload, so it archives
     | what it replaces exactly as any other edit does. "Never destructive" is
     | a consequence of routing it through the same path rather than a rule
     | anything has to remember.
     */
    it('records a restore as its own action and keeps the version it came from', function () {
        ['owner' => $owner, 'secret' => $secret] = historyFixture();

        $this->actingAs($owner)->patch("/secrets/{$secret->uuid}", editPayload($secret));

        $secret->refresh();

        $this->actingAs($owner)
            ->patch("/secrets/{$secret->uuid}", editPayload($secret, ['restored_from' => 1]))
            ->assertRedirect();

        $event = AuditEvent::query()->where('action', AuditAction::SecretRestored)->sole();

        expect($event->decodedMetadata())->toBe(['restored_from' => 1, 'version' => 3])
            ->and($secret->versions()->pluck('version')->sort()->values()->all())->toBe([1, 2]);
    });

    it('lets a viewer read history but not erase it', function () {
        ['vault' => $vault, 'secret' => $secret] = historyFixture();

        $viewer = User::factory()->create();
        $vault->memberships()->create([
            'uuid' => (string) Str::uuid7(),
            'user_id' => $viewer->getKey(),
            'role' => VaultRole::Viewer,
            'wrapped_vault_key' => EnvelopeFixtures::sealedEnvelope(),
            'key_epoch' => $vault->key_epoch,
        ]);

        SecretVersion::factory()->for($secret)->create();

        $this->actingAs($viewer)->get("/secrets/{$secret->uuid}/history")->assertSuccessful();
        $this->actingAs($viewer)->delete("/secrets/{$secret->uuid}/history")->assertNotFound();

        expect($secret->versions()->count())->toBe(1);
    });

    it('hides a secret’s history from someone outside the vault', function () {
        ['secret' => $secret] = historyFixture();

        $stranger = User::factory()->create();

        $this->actingAs($stranger)->get("/secrets/{$secret->uuid}/history")->assertNotFound();
    });
});

describe('purging', function () {
    /*
     | The one destructive action in the application with no grace period, and
     | deliberately so: the case it exists for is a credential rotated because
     | it leaked, and keeping the leaked value for another thirty days is
     | exactly the state the user is trying to get out of.
     */
    it('erases every version at once and leaves the secret alone', function () {
        ['owner' => $owner, 'secret' => $secret] = historyFixture();

        SecretVersion::factory()->count(3)->for($secret)->sequence(
            ['version' => 1], ['version' => 2], ['version' => 3],
        )->create();

        $live = $secret->payload_ct->base64;

        $this->actingAs($owner)->delete("/secrets/{$secret->uuid}/history")->assertRedirect();

        expect($secret->versions()->count())->toBe(0)
            ->and($secret->refresh()->payload_ct->base64)->toBe($live);
    });

    it('records that history was erased, and how much, but nothing of what it held', function () {
        ['owner' => $owner, 'secret' => $secret] = historyFixture();

        SecretVersion::factory()->count(2)->for($secret)->sequence(
            ['version' => 1], ['version' => 2],
        )->create();

        $this->actingAs($owner)->delete("/secrets/{$secret->uuid}/history");

        $event = AuditEvent::query()->where('action', AuditAction::SecretHistoryPurged)->sole();

        expect($event->decodedMetadata())->toBe(['count' => 2])
            ->and($event->subject_uuid)->toBe($secret->uuid);
    });
});

describe('retention', function () {
    it('trims to the vault’s count as soon as an edit pushes past it', function () {
        ['owner' => $owner, 'vault' => $vault, 'secret' => $secret] = historyFixture();

        $vault->forceFill(['history_max_versions' => 2])->save();

        foreach (range(1, 4) as $ignored) {
            $this->actingAs($owner)->patch("/secrets/{$secret->uuid}", editPayload($secret->refresh()));
        }

        expect($secret->versions()->pluck('version')->sort()->values()->all())->toBe([3, 4]);
    });

    it('keeps nothing at all for a vault that has turned history off', function () {
        ['owner' => $owner, 'vault' => $vault, 'secret' => $secret] = historyFixture();

        $vault->forceFill(['history_max_versions' => 0])->save();

        $this->actingAs($owner)->patch("/secrets/{$secret->uuid}", editPayload($secret))->assertRedirect();

        expect($secret->versions()->count())->toBe(0)
            ->and($secret->refresh()->current_version)->toBe(2);
    });

    it('follows the deployment default when the vault has no opinion', function () {
        ['vault' => $vault] = historyFixture();

        config()->set('vault.history.max_versions', 7);
        config()->set('vault.history.max_age_days', 90);

        expect($vault->historyMaxVersions())->toBe(7)
            ->and($vault->historyMaxAgeDays())->toBe(90);
    });

    /*
     | Shortening a policy applies to what is already stored, immediately. A
     | setting that waited for the next edit or the next sweep would report a
     | number that was not true, to somebody who is usually changing it
     | *because* of what is in there.
     */
    it('prunes what is already stored when the policy is shortened', function () {
        ['owner' => $owner, 'vault' => $vault, 'secret' => $secret] = historyFixture();

        SecretVersion::factory()->count(5)->for($secret)->sequence(
            ['version' => 1], ['version' => 2], ['version' => 3], ['version' => 4], ['version' => 5],
        )->create();

        $this->actingAs($owner)
            ->patch("/vaults/{$vault->uuid}/history", ['max_versions' => 2, 'max_age_days' => 30])
            ->assertRedirect();

        $event = AuditEvent::query()->where('action', AuditAction::VaultRetentionChanged)->sole();

        expect($secret->versions()->pluck('version')->sort()->values()->all())->toBe([4, 5])
            ->and($event->decodedMetadata())
            ->toBe(['count' => 3, 'max_age_days' => 30, 'max_versions' => 2]);
    });

    it('lets an empty setting hand the vault back to the deployment default', function () {
        ['owner' => $owner, 'vault' => $vault] = historyFixture();

        $vault->forceFill(['history_max_versions' => 3, 'history_max_age_days' => 10])->save();

        $this->actingAs($owner)
            ->patch("/vaults/{$vault->uuid}/history", ['max_versions' => null, 'max_age_days' => null])
            ->assertRedirect();

        $vault->refresh();

        expect($vault->history_max_versions)->toBeNull()
            ->and($vault->historyMaxVersions())->toBe(config()->integer('vault.history.max_versions'));
    });

    it('keeps an editor away from the retention policy', function () {
        ['vault' => $vault] = historyFixture();

        $editor = User::factory()->create();
        $vault->memberships()->create([
            'uuid' => (string) Str::uuid7(),
            'user_id' => $editor->getKey(),
            'role' => VaultRole::Editor,
            'wrapped_vault_key' => EnvelopeFixtures::sealedEnvelope(),
            'key_epoch' => $vault->key_epoch,
        ]);

        $this->actingAs($editor)
            ->patch("/vaults/{$vault->uuid}/history", ['max_versions' => 0, 'max_age_days' => 30])
            ->assertNotFound();

        expect($vault->refresh()->history_max_versions)->toBeNull();
    });
});

describe('the retention sweep', function () {
    it('removes versions older than the vault keeps, and says why', function () {
        ['vault' => $vault, 'secret' => $secret] = historyFixture();

        $vault->forceFill(['history_max_age_days' => 30])->save();

        SecretVersion::factory()->for($secret)->archivedDaysAgo(60)->create(['version' => 1]);
        SecretVersion::factory()->for($secret)->archivedDaysAgo(5)->create(['version' => 2]);

        expect(pruneHistory())->toBe(0)
            ->and($secret->versions()->pluck('version')->all())->toBe([2]);

        $event = AuditEvent::query()->where('action', AuditAction::SecretHistoryPruned)->sole();

        expect($event->decodedMetadata())->toBe(['count' => 1, 'reason' => 'expired'])
            /*
             | No actor. Nobody did this — time did — and attributing a deletion
             | to whoever last edited the secret would put a name in the log
             | against something they did not do.
             */
            ->and($event->actor_uuid)->toBeNull();
    });

    it('changes nothing on a dry run', function () {
        ['vault' => $vault, 'secret' => $secret] = historyFixture();

        $vault->forceFill(['history_max_age_days' => 30])->save();

        SecretVersion::factory()->for($secret)->archivedDaysAgo(60)->create(['version' => 1]);

        expect(pruneHistory(['--dry-run' => true]))->toBe(0)
            ->and($secret->versions()->count())->toBe(1)
            ->and(AuditEvent::query()->where('action', AuditAction::SecretHistoryPruned)->count())
            ->toBe(0);
    });

    /*
     | Trashed vaults are swept too. A vault in its deletion grace period is
     | still storing every old password it ever held, and pausing retention
     | because somebody clicked delete would keep the data *longer*.
     */
    it('sweeps a vault that is in its deletion grace period', function () {
        ['vault' => $vault, 'secret' => $secret] = historyFixture();

        $vault->forceFill(['history_max_age_days' => 30])->save();
        SecretVersion::factory()->for($secret)->archivedDaysAgo(60)->create(['version' => 1]);

        $vault->delete();

        expect(pruneHistory())->toBe(0)
            ->and($secret->versions()->count())->toBe(0);
    });

    it('catches a history sitting above the count with nothing to trigger a trim', function () {
        ['vault' => $vault, 'secret' => $secret] = historyFixture();

        SecretVersion::factory()->count(4)->for($secret)->sequence(
            ['version' => 1], ['version' => 2], ['version' => 3], ['version' => 4],
        )->create();

        $vault->forceFill(['history_max_versions' => 2])->saveQuietly();

        expect(pruneHistory())->toBe(0)
            ->and($secret->versions()->pluck('version')->sort()->values()->all())->toBe([3, 4]);

        $event = AuditEvent::query()->where('action', AuditAction::SecretHistoryPruned)->sole();

        expect($event->decodedMetadata())->toBe(['count' => 2, 'reason' => 'retained']);
    });
});

/**
 * Runs the sweep and returns its exit code.
 *
 * Through `Artisan::call` rather than `$this->artisan()`: the latter returns a
 * PendingCommand that defers execution to its destructor, so a forgotten
 * assertion means the command silently never ran and the test passes on a
 * database nothing touched.
 *
 * @param  array<string, mixed>  $options
 */
function pruneHistory(array $options = []): int
{
    return Artisan::call('vault:history-prune', $options);
}
