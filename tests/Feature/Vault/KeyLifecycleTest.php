<?php

use App\Enums\VaultRole;
use App\Models\Lockbox;
use App\Models\User;
use App\Models\UserIdentity;
use App\Models\Vault;
use App\Rules\Envelope;
use Database\Factories\EnvelopeFixtures;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Inertia\Testing\AssertableInertia;

/**
 * The rotation lifecycle: voluntary re-keys, reminders, and the two commands
 * that report what the server can see.
 *
 * The load-bearing claim in `vault:verify-keys` is a negative, and it is worth
 * stating in a test file as well as in the command's own output: **the server
 * cannot check that a key opens what it claims to.** It holds none of them.
 * Everything below is structural — epochs, membership, envelope headers — and
 * the value of the command is that each fault it does find has a real
 * consequence somebody has to act on.
 */

/** A fully healthy vault: an owner with keys, at the current epoch. */
function healthyVault(): Vault
{
    $owner = User::factory()->create();
    UserIdentity::factory()->for($owner)->create();

    return Vault::factory()->ownedBy($owner)->create();
}

/** The vault's owner, as a User rather than a nullable relation. */
function ownerOf(Vault $vault): User
{
    return User::query()->whereKey($vault->owner_id)->sole();
}

/**
 * Runs a command and returns its exit code.
 *
 * `Artisan::call` rather than `$this->artisan(...)`, for the reason recorded in
 * FileTest: the latter defers the run to a destructor, so a test that forgets to
 * assert on it silently never runs the command at all.
 *
 * @param  array<string, mixed>  $options
 */
function runCommand(string $command, array $options = []): int
{
    return Artisan::call($command, $options);
}

describe('when a key was last rotated', function () {
    it('records creation as the starting point', function () {
        $user = User::factory()->create();

        $this->actingAs($user)->post('/vaults', [
            'uuid' => (string) Str::uuid7(),
            'membership_uuid' => (string) Str::uuid7(),
            'payload_ct' => EnvelopeFixtures::envelope(120),
            'wrapped_item_key' => EnvelopeFixtures::envelope(48),
            'wrapped_vault_key' => EnvelopeFixtures::sealedEnvelope(),
            'payload_version' => 1,
        ])->assertRedirect();

        expect(Vault::query()->sole()->key_rotated_at)->not->toBeNull();
    });

    /*
     | Without a column that means only this, "has this key been the same since
     | 2026" is unanswerable: `key_epoch` says how many times a vault has rotated
     | and `updated_at` moves for a rename.
     */
    it('is not disturbed by an ordinary edit', function () {
        $vault = healthyVault();
        $vault->forceFill(['key_rotated_at' => now()->subYear()])->save();
        $before = $vault->key_rotated_at;

        $this->actingAs(ownerOf($vault))->patch("/vaults/{$vault->uuid}", [
            'payload_ct' => EnvelopeFixtures::envelope(120),
            'wrapped_item_key' => EnvelopeFixtures::envelope(48),
            'payload_version' => 1,
        ])->assertRedirect();

        expect($vault->refresh()->key_rotated_at?->timestamp)->toBe($before?->timestamp);
    });
});

describe('the rotation reminder', function () {
    it('is off by default, because a calendar does not re-protect anything', function () {
        Config::set('vault.rotation.after_days', 0);

        $vault = healthyVault();
        $vault->forceFill(['key_rotated_at' => now()->subYears(5)])->save();

        expect($vault->isRotationDue())->toBeFalse()
            ->and($vault->rotationDueAt())->toBeNull();
    });

    it('falls due once a vault has asked for one', function () {
        $vault = healthyVault();

        $this->actingAs(ownerOf($vault))
            ->patch("/vaults/{$vault->uuid}/rekey/schedule", ['after_days' => 30])
            ->assertRedirect();

        $vault->refresh()->forceFill(['key_rotated_at' => now()->subDays(31)])->save();

        expect($vault->refresh()->isRotationDue())->toBeTrue();
    });

    /*
     | Null and 0 are both falsy and mean opposite things: follow the
     | deployment's default, or never remind me. A control where one silently
     | becomes the other is a control somebody will set wrong.
     */
    it('distinguishes "use the default" from "never"', function () {
        Config::set('vault.rotation.after_days', 90);
        $vault = healthyVault();

        $this->actingAs(ownerOf($vault))->patch("/vaults/{$vault->uuid}/rekey/schedule", ['after_days' => null]);
        expect($vault->refresh()->rotateAfterDays())->toBe(90);

        $this->actingAs(ownerOf($vault))->patch("/vaults/{$vault->uuid}/rekey/schedule", ['after_days' => 0]);
        expect($vault->refresh()->rotateAfterDays())->toBe(0)
            ->and($vault->rotate_after_days)->toBe(0);
    });

    it('refuses an interval short enough to become background noise', function () {
        $vault = healthyVault();

        $this->actingAs(ownerOf($vault))
            ->patch("/vaults/{$vault->uuid}/rekey/schedule", ['after_days' => 1])
            ->assertSessionHasErrors('after_days');
    });

    it('is an administrator setting, and answers 404 to anyone else', function () {
        $vault = healthyVault();
        $editor = User::factory()->create();
        $vault->memberships()->create([
            'uuid' => (string) Str::uuid7(),
            'user_id' => $editor->getKey(),
            'role' => VaultRole::Editor,
            'wrapped_vault_key' => EnvelopeFixtures::sealedEnvelope(),
            'key_epoch' => $vault->key_epoch,
        ]);

        $this->actingAs($editor)
            ->patch("/vaults/{$vault->uuid}/rekey/schedule", ['after_days' => 30])
            ->assertNotFound();
    });
});

describe('rotating on demand', function () {
    /*
     | The whole point of Phase 10: rotation as a routine operation rather than
     | an emergency one. An operation you can only reach by first removing
     | somebody is not routine.
     */
    it('is reachable without a revocation having happened', function () {
        $vault = healthyVault();

        expect($vault->rekey_required_at)->toBeNull();

        $this->actingAs(ownerOf($vault))
            ->get("/vaults/{$vault->uuid}/rekey")
            ->assertOk()
            ->assertInertia(fn (AssertableInertia $page) => $page->where('required', false));
    });

    it('tells the page when a revocation demanded it instead', function () {
        $vault = healthyVault();
        $vault->forceFill(['rekey_required_at' => now()])->save();

        $this->actingAs(ownerOf($vault))
            ->get("/vaults/{$vault->uuid}/rekey")
            ->assertInertia(fn (AssertableInertia $page) => $page->where('required', true));
    });
});

describe('vault:verify-keys', function () {
    it('passes a healthy vault', function () {
        healthyVault();

        expect(runCommand('vault:verify-keys'))->toBe(0);
    });

    /*
     | A live membership on an old epoch holds access that silently does not
     | work: their sealed key opens nothing written since the rotation, and no
     | error tells them so.
     */
    it('reports a membership stranded on an old epoch', function () {
        $vault = healthyVault();
        $vault->forceFill(['key_epoch' => 4])->save();

        expect(runCommand('vault:verify-keys'))->toBe(1)
            ->and(Artisan::output())->toContain('stranded on key epoch 1');
    });

    it('reports a vault that was told to re-key and never did', function () {
        $vault = healthyVault();
        $vault->forceFill(['rekey_required_at' => now()->subDays(9)])->save();

        expect(runCommand('vault:verify-keys'))->toBe(1)
            ->and(Artisan::output())->toContain('a re-key has been required for 9 days');
    });

    /*
     | Nobody can rotate it, share it or delete it — a vault that has quietly
     | become unadministrable, which nothing else in the application would
     | surface.
     */
    it('reports a vault with no live administrator', function () {
        $vault = healthyVault();
        DB::table('vault_memberships')->update(['role' => VaultRole::Editor->value]);

        expect(runCommand('vault:verify-keys'))->toBe(1)
            ->and(Artisan::output())->toContain('no live administrator');
    });

    it('reports a member who has published no keys to seal to', function () {
        $vault = healthyVault();
        ownerOf($vault)->identity?->delete();

        expect(runCommand('vault:verify-keys'))->toBe(1)
            ->and(Artisan::output())->toContain('no published keys');
    });

    it('reports a wrapped key that is not a readable envelope', function () {
        $vault = healthyVault();

        Lockbox::factory()->for($vault)->create();
        DB::table('lockboxes')->update(['wrapped_item_key' => base64_encode('nonsense')]);

        expect(runCommand('vault:verify-keys'))->toBe(1)
            ->and(Artisan::output())->toContain('not a readable envelope');
    });

    /*
     | Said on every run including a clean one, because "no faults found" invites
     | the reading "everything is fine" — and the limit a green result would let
     | somebody forget is the most important thing about this command.
     */
    it('states what it cannot check even when it finds nothing', function () {
        healthyVault();

        expect(runCommand('vault:verify-keys'))->toBe(0)
            ->and(Artisan::output())->toContain('This checks structure only');
    });

    it('can be narrowed to one vault', function () {
        $healthy = healthyVault();
        $broken = healthyVault();
        $broken->forceFill(['key_epoch' => 7])->save();

        expect(runCommand('vault:verify-keys', ['--vault' => $healthy->uuid]))->toBe(0)
            ->and(runCommand('vault:verify-keys', ['--vault' => $broken->uuid]))->toBe(1);
    });
});

describe('vault:health', function () {
    it('counts accounts whose stretching is behind the deployment', function () {
        Config::set('vault.kdf', ['m' => 65536, 't' => 3, 'p' => 1]);

        User::factory()->create(['kdf_params' => ['m' => 16384, 't' => 2, 'p' => 1]]);
        User::factory()->create(['kdf_params' => ['m' => 65536, 't' => 3, 'p' => 1]]);

        expect(runCommand('vault:health'))->toBe(0)
            ->and(Artisan::output())->toContain('1 on password stretching below');
    });

    /*
     | The number exists so that "does algorithm agility actually move anything"
     | has an answer that is a measurement rather than an assumption. It also
     | does not trend to zero on its own, and the command says so.
     */
    it('counts payloads still on the old envelope version', function () {
        $vault = healthyVault();
        Lockbox::factory()->for($vault)->create();

        // The factories write version 1 envelopes, which is what rows created
        // before Phase 10 look like.
        expect(runCommand('vault:health'))->toBe(0);

        expect(Artisan::output())
            ->toContain('2 payloads stored')
            ->toContain('2 on the old version, movable by a re-seal')
            ->toContain('stays on the old envelope indefinitely');
    });

    it('sees a payload written at the current version as current', function () {
        $vault = healthyVault();

        DB::table('vaults')->update([
            'payload_ct' => base64_encode(
                chr(Envelope::CURRENT_VERSION).chr(1).random_bytes(24 + 32)
            ),
        ]);

        expect(runCommand('vault:health'))->toBe(0)
            ->and(Artisan::output())->toContain('0 on the old version, movable by a re-seal');
    });

    it('separates a required re-key from an elapsed reminder', function () {
        $vault = healthyVault();
        $vault->forceFill(['rekey_required_at' => now()])->save();

        expect(runCommand('vault:health'))->toBe(0);

        expect(Artisan::output())
            ->toContain('1 waiting on a re-key demanded by a revocation')
            ->toContain('A required re-key is not a reminder');
    });
});
