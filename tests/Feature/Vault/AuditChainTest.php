<?php

use App\Enums\AuditAction;
use App\Enums\VaultRole;
use App\Models\AuditEvent;
use App\Models\Lockbox;
use App\Models\Secret;
use App\Models\User;
use App\Models\Vault;
use App\Support\AuditChain;
use App\Support\AuditLog;
use App\Support\AuditMetadata;
use Database\Factories\EnvelopeFixtures;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

/**
 * The audit chain, and the four ways of tampering with it that it must catch.
 *
 * The corruption tests here go **around** the model on purpose, with raw query
 * builder writes. `AuditEvent` refuses to be updated or deleted, which is the
 * point of it — but a guard in application code is not what an attacker with a
 * database connection is subject to, and a test that only exercised the guard
 * would prove nothing about the chain itself.
 */
function chainOf(int $count = 3): User
{
    $user = User::factory()->create();
    $vault = Vault::factory()->create(['owner_id' => $user->getKey()]);

    $vault->memberships()->create([
        'uuid' => (string) Str::uuid7(),
        'user_id' => $user->getKey(),
        'role' => VaultRole::Owner,
        'wrapped_vault_key' => EnvelopeFixtures::sealedEnvelope(),
        'key_epoch' => $vault->key_epoch,
        'accepted_at' => now(),
    ]);

    for ($i = 0; $i < $count; $i++) {
        AuditLog::record(AuditAction::VaultUpdated, $vault, [], $user);
    }

    return $user;
}

function verify(): int
{
    return Artisan::call('vault:audit-verify');
}

describe('appending', function () {
    it('starts from the genesis hash and chains each entry to the last', function () {
        $user = User::factory()->create();

        $first = AuditLog::record(AuditAction::LoggedIn, $user, [], $user);
        $second = AuditLog::record(AuditAction::LoggedOut, $user, [], $user);

        expect($first->seq)->toBe(1)
            ->and($first->prev_hash)->toBe(base64_encode(AuditChain::genesisHash()))
            ->and($second->seq)->toBe(2)
            ->and($second->prev_hash)->toBe($first->hash);

        // And the head follows the last entry, which is the only thing that
        // notices a chain truncated from the end.
        expect(AuditLog::head()->seq)->toBe(2)
            ->and(AuditLog::head()->hash)->toBe($second->hash);
    });

    it('allocates seq gaplessly', function () {
        chainOf(5);

        expect(AuditEvent::query()->orderBy('seq')->pluck('seq')->all())->toBe([1, 2, 3, 4, 5]);
    });

    /*
     | The whole reason `metadata` is a `text` column holding canonical JSON
     | rather than a `json` one: the chain hashes those bytes exactly as stored,
     | and a column type that reordered keys would invalidate the chain from
     | that row on. Same trap as `vault_memberships.grant_payload`.
     */
    it('stores metadata as the exact bytes it hashes', function () {
        $user = User::factory()->create();

        $event = AuditLog::record(AuditAction::LoggedIn, $user, ['second_factor' => true], $user);

        expect(DB::table('audit_events')->where('seq', $event->seq)->value('metadata'))
            ->toBe('{"second_factor":true}');
    });

    it('sorts metadata keys so the same facts always hash the same', function () {
        expect(AuditMetadata::canonicalise(['role' => 'owner', 'key_epoch' => 2]))
            ->toBe(AuditMetadata::canonicalise(['key_epoch' => 2, 'role' => 'owner']));
    });
});

/**
 * The exit criteria. Each of these is a different kind of tampering, and each
 * has to be caught by a different property of the chain.
 */
describe('detecting tampering', function () {
    it('verifies a chain nobody has touched', function () {
        chainOf(4);

        expect(verify())->toBe(0);
    });

    it('detects a modified row', function () {
        chainOf(3);

        // The metadata of the middle entry, rewritten in place. Every field is
        // inside the hash, so any of them would do.
        DB::table('audit_events')->where('seq', 2)->update(['metadata' => '{"count":99}']);

        expect(verify())->toBe(1);
    });

    it('detects a deleted row', function () {
        chainOf(4);

        DB::table('audit_events')->where('seq', 2)->delete();

        // Caught by the gap in `seq` before the hashes are even consulted —
        // which is why `seq` is gapless rather than merely increasing.
        expect(verify())->toBe(1);
    });

    it('detects two rows reordered', function () {
        chainOf(4);

        $second = DB::table('audit_events')->where('seq', 2)->first();
        $third = DB::table('audit_events')->where('seq', 3)->first();

        /*
         | Swapping the sequence numbers, so nothing is missing and the count is
         | unchanged. Only the hash of the *contents* against the hash of what
         | came before catches this one.
         */
        DB::table('audit_events')->where('seq', 2)->update(['seq' => 999]);
        DB::table('audit_events')->where('seq', 3)->update(['seq' => 2]);
        DB::table('audit_events')->where('seq', 999)->update(['seq' => 3]);

        expect($second)->not->toBeNull()
            ->and($third)->not->toBeNull()
            ->and(verify())->toBe(1);
    });

    /*
     | Truncation from the end is the one kind of tampering the chain cannot
     | catch on its own: what remains is a perfectly valid shorter chain, and
     | every hash still follows from the one before it. Only a record of where
     | the chain *used to* reach gives it away — the stored head here, and the
     | anchor mailed to the operator for when the head is rewritten too.
     */
    it('detects entries removed from the end', function () {
        chainOf(4);

        DB::table('audit_events')->where('seq', '>', 2)->delete();

        expect(verify())->toBe(1);
    });

    it('detects a rewritten head', function () {
        chainOf(3);

        DB::table('audit_chain')->where('id', 1)->update([
            'head_hash' => base64_encode(random_bytes(32)),
        ]);

        expect(verify())->toBe(1);
    });
});

describe('append-only enforcement', function () {
    it('refuses to update an event through the model', function () {
        $user = User::factory()->create();
        $event = AuditLog::record(AuditAction::LoggedIn, $user, [], $user);

        expect(fn () => $event->update(['action' => AuditAction::LoggedOut]))
            ->toThrow(RuntimeException::class, 'append-only');
    });

    it('refuses to delete an event through the model', function () {
        $user = User::factory()->create();
        $event = AuditLog::record(AuditAction::LoggedIn, $user, [], $user);

        expect(fn () => $event->delete())->toThrow(RuntimeException::class, 'append-only');
    });

    /*
     | Closing an account must not rewrite the rows it touched. A nullable
     | foreign key with `nullOnDelete` would do exactly that, and the chain
     | would report tampering because somebody left.
     */
    it('survives the deletion of the account that acted', function () {
        $user = User::factory()->create();

        AuditLog::record(AuditAction::LoggedIn, $user, [], $user);
        AuditLog::record(AuditAction::LoggedOut, $user, [], $user);

        $uuid = $user->uuid;
        $user->delete();

        expect(verify())->toBe(0)
            ->and(AuditEvent::query()->where('seq', 1)->value('actor_uuid'))->toBe($uuid);
    });
});

describe('metadata', function () {
    /*
     | The linter. `metadata` is a free-form JSON column next to controllers
     | that have the whole request in scope, which makes it the shortest path in
     | this project from decrypted content to a permanent, append-only record of
     | it. The keys are a closed set for that reason.
     */
    it('refuses a key nobody declared', function () {
        $user = User::factory()->create();

        expect(fn () => AuditLog::record(AuditAction::LoggedIn, $user, ['secret_name' => 'AWS root'], $user))
            ->toThrow(InvalidArgumentException::class, 'not declared');
    });

    it('refuses a declared key holding the wrong shape', function () {
        expect(fn () => AuditMetadata::canonicalise(['role' => 'superuser']))
            ->toThrow(InvalidArgumentException::class);

        expect(fn () => AuditMetadata::canonicalise(['key_epoch' => 'two']))
            ->toThrow(InvalidArgumentException::class);
    });

    /*
     | Every declared key, checked against the rule that decides membership:
     | could its value differ between two users doing the same thing to
     | different data? A count and an epoch cannot. A name or a note can, and
     | this asserts none of the declared keys is free text.
     */
    it('declares only structural keys', function () {
        foreach (AuditMetadata::declaredKeys() as $key) {
            expect($key)->not->toContain('name')
                ->and($key)->not->toContain('value')
                ->and($key)->not->toContain('note')
                ->and($key)->not->toContain('filename')
                ->and($key)->not->toContain('url')
                ->and($key)->not->toContain('query');
        }
    });

    /*
     | And the end-to-end version, which is what would actually catch a
     | regression: put a sentinel through the real endpoints and assert it never
     | lands in the log. The leak canary sweeps every table, so this is the
     | narrower question of whether audit metadata specifically stayed clean.
     */
    it('never records a value that came from the request body', function () {
        $sentinel = 'AUDIT-CANARY-'.Str::random(20);

        $user = User::factory()->create();
        $vault = Vault::factory()->create(['owner_id' => $user->getKey()]);

        $vault->memberships()->create([
            'uuid' => (string) Str::uuid7(),
            'user_id' => $user->getKey(),
            'role' => VaultRole::Owner,
            'wrapped_vault_key' => EnvelopeFixtures::sealedEnvelope(),
            'key_epoch' => $vault->key_epoch,
            'accepted_at' => now(),
        ]);

        $lockbox = Lockbox::factory()->create(['vault_id' => $vault->getKey()]);

        $this->actingAs($user)
            ->post("/lockboxes/{$lockbox->uuid}/secrets", [
                'uuid' => (string) Str::uuid7(),
                'payload_ct' => EnvelopeFixtures::envelope(96),
                'wrapped_item_key' => EnvelopeFixtures::envelope(48),
                'payload_version' => 2,
                // The shapes a careless client would send. None is a declared
                // metadata key, and none may reach the log by any route.
                'name' => $sentinel,
                'notes' => $sentinel,
                'filename' => $sentinel,
            ])
            ->assertRedirect();

        $log = DB::table('audit_events')->get()->map(fn (object $row): string => json_encode($row) ?: '');

        expect($log)->not->toBeEmpty()
            ->and($log->implode(''))->not->toContain($sentinel);
    });
});

describe('what gets recorded', function () {
    it('records the CRUD verbs against their own subjects', function () {
        $user = User::factory()->create();
        $vault = Vault::factory()->create(['owner_id' => $user->getKey()]);

        $vault->memberships()->create([
            'uuid' => (string) Str::uuid7(),
            'user_id' => $user->getKey(),
            'role' => VaultRole::Owner,
            'wrapped_vault_key' => EnvelopeFixtures::sealedEnvelope(),
            'key_epoch' => $vault->key_epoch,
            'accepted_at' => now(),
        ]);

        $lockbox = Lockbox::factory()->create(['vault_id' => $vault->getKey()]);
        $secret = Secret::factory()->create(['lockbox_id' => $lockbox->getKey()]);

        $this->actingAs($user)->delete("/secrets/{$secret->uuid}")->assertRedirect();
        $this->actingAs($user)->delete("/lockboxes/{$lockbox->uuid}")->assertRedirect();

        $recorded = AuditEvent::query()->orderBy('seq')->get();

        expect($recorded->map(fn (AuditEvent $event): string => $event->action->value)->all())
            ->toBe(['secret.deleted', 'lockbox.deleted'])
            ->and($recorded->pluck('subject_type')->all())->toBe(['secret', 'lockbox'])
            ->and($recorded->first()?->actor_uuid)->toBe($user->uuid)
            ->and(verify())->toBe(0);
    });

    it('records a failed sign-in with no actor when the address is unknown', function () {
        $this->postJson('/login', [
            'email' => 'nobody@example.com',
            'auth_key' => base64_encode(random_bytes(32)),
        ])->assertStatus(422);

        $event = AuditEvent::query()->sole();

        expect($event->action)->toBe(AuditAction::LoginFailed)
            ->and($event->actor_uuid)->toBeNull()
            // The address is deliberately absent: a log full of attempted
            // addresses is a list of who has an account, assembled by whoever
            // was guessing.
            ->and($event->metadata)->toBe('{}')
            ->and($event->ip_hash)->not->toBeNull();
    });

    /*
     | An address is never stored, only a keyed hash of it. Keyed, because an
     | unkeyed hash of an IPv4 address is not a pseudonym — the whole space is
     | 2^32 and enumerating it takes seconds.
     */
    it('stores a keyed fingerprint of the address rather than the address', function () {
        $user = User::factory()->create();

        AuditLog::record(AuditAction::LoggedIn, $user, [], $user);

        $stored = AuditEvent::query()->sole()->ip_hash;

        expect($stored)->not->toBeNull()
            ->and($stored)->not->toContain('127.0.0.1')
            ->and($stored)->toBe(AuditChain::fingerprint('127.0.0.1'));
    });
});

describe('the anchor', function () {
    it('prints the head so an operator has a record the server does not hold', function () {
        chainOf(2);

        $head = AuditLog::head();

        Artisan::call('vault:audit-anchor', ['--print' => true]);

        expect(Artisan::output())->toContain($head->hash)->toContain('seq  2');
    });

    /*
     | An anchoring job that reports success while doing nothing is worse than
     | no job: the operator believes there is an external record, and there is
     | not. So an unconfigured address is a failure, loudly.
     */
    it('fails rather than quietly doing nothing when no address is configured', function () {
        config(['vault.audit.anchor_address' => '']);

        expect(Artisan::call('vault:audit-anchor'))->toBe(1);
    });
});
