<?php

use App\Enums\VaultRole;
use App\Models\Lockbox;
use App\Models\Secret;
use App\Models\SecretVersion;
use App\Models\User;
use App\Models\UserIdentity;
use App\Models\Vault;
use App\Models\VaultFile;
use App\Models\VaultMembership;
use Database\Factories\EnvelopeFixtures;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

/**
 * Rotating a vault key, and the guarantee that it is all or nothing.
 *
 * The 2017 application had a `vault:key` command that walked a vault
 * re-encrypting item by item. Interrupt it and the vault was left in a mixed
 * state, with no record of which items were on which key and no way to resume
 * safely. This phase's answer is to make the operation atomic — one request, one
 * transaction, accepted only at exactly `key_epoch + 1` with a complete set —
 * and these tests are what hold that answer in place.
 */

/**
 * A vault with two lockboxes, three secrets and a second member.
 *
 * @return array{owner: User, member: User, vault: Vault, membership: VaultMembership, items: array<int, string>}
 */
function rekeyFixture(): array
{
    $owner = User::factory()->create();
    UserIdentity::factory()->for($owner)->create();

    $member = User::factory()->create();
    UserIdentity::factory()->for($member)->create();

    $vault = Vault::factory()->ownedBy($owner)->create();

    $membership = $vault->memberships()->create([
        'uuid' => (string) Str::uuid7(),
        'user_id' => $member->getKey(),
        'role' => VaultRole::Editor,
        'wrapped_vault_key' => EnvelopeFixtures::sealedEnvelope(),
        'key_epoch' => $vault->key_epoch,
        'granted_by' => $owner->getKey(),
    ]);

    $items = [];

    foreach (range(1, 2) as $ignored) {
        $lockbox = Lockbox::factory()->for($vault)->create();
        $items[] = $lockbox->uuid;

        foreach (range(1, 2) as $alsoIgnored) {
            $items[] = Secret::factory()->for($lockbox)->create()->uuid;
        }
    }

    return compact('owner', 'member', 'vault', 'membership', 'items');
}

/**
 * @param  array{owner: User, member: User, vault: Vault, membership: VaultMembership, items: array<int, string>}  $fixture
 * @param  array<string, mixed>  $overrides
 * @return array<string, mixed>
 */
function rekeyPayload(array $fixture, array $overrides = []): array
{
    return [
        'key_epoch' => $fixture['vault']->key_epoch + 1,
        'vault_wrapped_item_key' => EnvelopeFixtures::envelope(48),
        'items' => array_map(fn (string $uuid): array => [
            'uuid' => $uuid,
            'wrapped_item_key' => EnvelopeFixtures::envelope(48),
        ], $fixture['items']),
        'memberships' => array_map(
            fn (string $uuid): array => [
                'uuid' => $uuid,
                'wrapped_vault_key' => EnvelopeFixtures::sealedEnvelope(),
            ],
            liveMembershipUuids($fixture['vault']),
        ),
        ...$overrides,
    ];
}

/**
 * Reads one of the request's row lists back out as a typed array.
 *
 * @param  array<string, mixed>  $payload
 * @return array<int, array<string, string>>
 */
function itemsOf(array $payload, string $key = 'items'): array
{
    $rows = $payload[$key] ?? [];
    $typed = [];

    foreach (is_array($rows) ? $rows : [] as $row) {
        if (! is_array($row)) {
            continue;
        }

        $fields = [];

        foreach ($row as $field => $value) {
            if (is_string($field) && is_string($value)) {
                $fields[$field] = $value;
            }
        }

        $typed[] = $fields;
    }

    return $typed;
}

/**
 * @return array<int, string>
 */
function liveMembershipUuids(Vault $vault): array
{
    return $vault->memberships()
        ->whereNull('revoked_at')
        ->get()
        ->map(fn (VaultMembership $membership): string => $membership->uuid)
        ->all();
}

/**
 * Every wrapped key in the vault, as one comparable snapshot.
 *
 * @return array<string, string>
 */
function wrappedKeys(Vault $vault): array
{
    $keys = ['vault' => $vault->refresh()->wrapped_item_key->base64];

    foreach (Lockbox::withTrashed()->where('vault_id', $vault->getKey())->get() as $lockbox) {
        $keys[$lockbox->uuid] = $lockbox->wrapped_item_key->base64;

        foreach (Secret::withTrashed()->where('lockbox_id', $lockbox->getKey())->get() as $secret) {
            $keys[$secret->uuid] = $secret->wrapped_item_key->base64;
        }
    }

    foreach ($vault->memberships()->get() as $membership) {
        $keys["member:{$membership->uuid}"] = $membership->wrapped_vault_key->base64;
    }

    return $keys;
}

describe('a complete re-key', function () {
    /**
     * The exit criterion, stated as an assertion: after rotation, every single
     * wrapped key is a different ciphertext and the epoch has advanced. A cached
     * copy of the old Vault Key opens none of them.
     */
    it('replaces every wrapped key and advances the epoch', function () {
        $fixture = rekeyFixture();
        $before = wrappedKeys($fixture['vault']);

        $this->actingAs($fixture['owner'])
            ->post("/vaults/{$fixture['vault']->uuid}/rekey", rekeyPayload($fixture))
            ->assertRedirect();

        $after = wrappedKeys($fixture['vault']);

        expect(array_keys($after))->toBe(array_keys($before));

        foreach ($before as $name => $key) {
            expect($after[$name])->not->toBe($key, "{$name} was not re-wrapped");
        }

        expect($fixture['vault']->refresh()->key_epoch)->toBe(2)
            ->and($fixture['vault']->refresh()->rekey_required_at)->toBeNull();
    });

    /**
     * Rotation is cheap precisely because it does not touch payloads: for a
     * 500-item vault it is 500 × 32 bytes of re-wrapping rather than
     * re-encrypting every secret. If this ever failed, the operation would have
     * quietly become one that needs every plaintext.
     */
    it('leaves every payload ciphertext untouched', function () {
        $fixture = rekeyFixture();

        /*
         | Ordered by UUID, because the claim is about a set of ciphertexts and
         | not about the order rows come back in. Without it this compares two
         | maps whose keys are in whatever order the planner chose, and `toBe`
         | on an array is order-sensitive: it passed on SQLite and on Postgres
         | in isolation, and failed in a full Postgres run once earlier writes
         | had rearranged the heap. A flake that only appears in CI is worse
         | than a failure.
         */
        $payloads = fn (): array => Secret::query()
            ->orderBy('uuid')
            ->get()
            ->mapWithKeys(fn (Secret $secret): array => [$secret->uuid => $secret->payload_ct->base64])
            ->all();

        $before = $payloads();

        $this->actingAs($fixture['owner'])
            ->post("/vaults/{$fixture['vault']->uuid}/rekey", rekeyPayload($fixture));

        expect($payloads())->toBe($before);
    });

    it('moves every remaining member to the new epoch', function () {
        $fixture = rekeyFixture();

        $this->actingAs($fixture['owner'])
            ->post("/vaults/{$fixture['vault']->uuid}/rekey", rekeyPayload($fixture));

        expect($fixture['vault']->memberships()->pluck('key_epoch')->all())->toBe([2, 2]);
    });

    /**
     * During the deletion grace period a trashed item is still a row holding a
     * key wrapped under the *old* Vault Key. Skipping it would turn "deleted,
     * restorable for 30 days" into "deleted", without anyone choosing that.
     */
    it('covers items in the deletion grace period', function () {
        $fixture = rekeyFixture();

        $secret = Secret::query()->firstOrFail();
        $secret->delete();

        expect($fixture['items'])->toContain($secret->uuid);

        $before = $secret->wrapped_item_key->base64;

        $this->actingAs($fixture['owner'])
            ->post("/vaults/{$fixture['vault']->uuid}/rekey", rekeyPayload($fixture))
            ->assertRedirect();

        $restored = Secret::withTrashed()->whereKey($secret->getKey())->sole();

        expect($restored->wrapped_item_key->base64)->not->toBe($before);
    });
});

/**
 * The two item kinds that do not appear on the page an owner is looking at when
 * they rotate.
 *
 * A file attachment and an archived version each hold an Item Key wrapped under
 * the Vault Key, exactly as a live secret does. Neither is visible from the
 * vault view, which is precisely why both are easy to leave out of the rotation
 * set — and a rotation that left either out would report success and quietly
 * make every attachment and every previous password in the vault unopenable.
 * The failure mode is identical to skipping trashed rows, arriving by a
 * different route, so it gets the same treatment: the server refuses an
 * incomplete set rather than trusting the client to have found everything.
 */
describe('the items nobody remembers', function () {
    it('refuses a re-key that leaves out an attachment or an archived version', function () {
        $fixture = rekeyFixture();
        $secret = Secret::query()->firstOrFail();

        SecretVersion::factory()->for($secret)->create();
        VaultFile::factory()->for($secret->lockbox)->create();

        $this->actingAs($fixture['owner'])
            ->post("/vaults/{$fixture['vault']->uuid}/rekey", rekeyPayload($fixture))
            ->assertSessionHasErrors('items');

        expect($fixture['vault']->refresh()->key_epoch)->toBe(1);
    });

    it('re-wraps them when they are included', function () {
        $fixture = rekeyFixture();
        $secret = Secret::query()->firstOrFail();

        $version = SecretVersion::factory()->for($secret)->create();
        $file = VaultFile::factory()->for($secret->lockbox)->create();

        $payload = rekeyPayload($fixture);
        $payload['items'] = [
            ...itemsOf($payload),
            ['uuid' => $version->uuid, 'wrapped_item_key' => EnvelopeFixtures::envelope(48)],
            ['uuid' => $file->uuid, 'wrapped_item_key' => EnvelopeFixtures::envelope(48)],
        ];

        $before = [$version->wrapped_item_key->base64, $file->wrapped_item_key->base64];

        $this->actingAs($fixture['owner'])
            ->post("/vaults/{$fixture['vault']->uuid}/rekey", $payload)
            ->assertRedirect();

        expect($version->refresh()->wrapped_item_key->base64)->not->toBe($before[0])
            ->and($file->refresh()->wrapped_item_key->base64)->not->toBe($before[1]);
    });

    /*
     | An archived version stays readable after the rotation that re-wrapped it,
     | which is the exit criterion for this phase stated as a property of the
     | stored row: its payload was never touched, only the 32 bytes that unlock
     | it. If the payload had moved, the version would be unopenable and nothing
     | would have said so.
     */
    it('leaves an archived payload byte-for-byte unchanged', function () {
        $fixture = rekeyFixture();
        $secret = Secret::query()->firstOrFail();
        $version = SecretVersion::factory()->for($secret)->create();

        $payload = rekeyPayload($fixture);
        $payload['items'] = [
            ...itemsOf($payload),
            ['uuid' => $version->uuid, 'wrapped_item_key' => EnvelopeFixtures::envelope(48)],
        ];

        $before = $version->payload_ct->base64;

        $this->actingAs($fixture['owner'])
            ->post("/vaults/{$fixture['vault']->uuid}/rekey", $payload)
            ->assertRedirect();

        expect($version->refresh()->payload_ct->base64)->toBe($before);
    });
});

describe('an incomplete re-key', function () {
    /**
     * The 2017 failure, as a test. Everything is submitted except one secret;
     * the vault must be left wholly on the old epoch rather than partly on each.
     */
    it('changes nothing at all when one item key is missing', function () {
        $fixture = rekeyFixture();
        $before = wrappedKeys($fixture['vault']);

        $payload = rekeyPayload($fixture);
        $items = itemsOf($payload);
        array_pop($items);
        $payload['items'] = $items;

        $this->actingAs($fixture['owner'])
            ->post("/vaults/{$fixture['vault']->uuid}/rekey", $payload)
            ->assertSessionHasErrors('items');

        expect(wrappedKeys($fixture['vault']))->toBe($before)
            ->and($fixture['vault']->refresh()->key_epoch)->toBe(1);
    });

    /**
     * "Nothing extra" matters as much as "nothing missing": a submission naming
     * an item that is not in this vault is a client working from a stale
     * picture, and the items it *did* send are then unlikely to be complete
     * either.
     */
    it('refuses a set naming an item that is not in the vault', function () {
        $fixture = rekeyFixture();
        $before = wrappedKeys($fixture['vault']);

        $payload = rekeyPayload($fixture);
        $payload['items'] = [...itemsOf($payload), [
            'uuid' => (string) Str::uuid7(),
            'wrapped_item_key' => EnvelopeFixtures::envelope(48),
        ]];

        $this->actingAs($fixture['owner'])
            ->post("/vaults/{$fixture['vault']->uuid}/rekey", $payload)
            ->assertSessionHasErrors('items');

        expect(wrappedKeys($fixture['vault']))->toBe($before);
    });

    it('changes nothing when a member is left out', function () {
        $fixture = rekeyFixture();
        $before = wrappedKeys($fixture['vault']);

        $payload = rekeyPayload($fixture);
        $memberships = itemsOf($payload, 'memberships');
        array_pop($memberships);
        $payload['memberships'] = $memberships;

        $this->actingAs($fixture['owner'])
            ->post("/vaults/{$fixture['vault']->uuid}/rekey", $payload)
            ->assertSessionHasErrors('memberships');

        expect(wrappedKeys($fixture['vault']))->toBe($before);
    });

    /**
     * A revoked member must not be re-keyed to — that would hand the person who
     * was just removed a working copy of the new key, which is the one outcome
     * the whole operation exists to prevent.
     */
    it('refuses a set that includes a revoked member', function () {
        $fixture = rekeyFixture();

        $this->actingAs($fixture['owner'])
            ->delete("/memberships/{$fixture['membership']->uuid}")
            ->assertRedirect();

        // Built before the revocation is accounted for: the stale set still
        // names the removed member.
        $payload = rekeyPayload($fixture, [
            'memberships' => [
                ['uuid' => $fixture['vault']->memberships()->whereNull('revoked_at')->value('uuid'),
                    'wrapped_vault_key' => EnvelopeFixtures::sealedEnvelope()],
                ['uuid' => $fixture['membership']->uuid,
                    'wrapped_vault_key' => EnvelopeFixtures::sealedEnvelope()],
            ],
        ]);

        $this->actingAs($fixture['owner'])
            ->post("/vaults/{$fixture['vault']->uuid}/rekey", $payload)
            ->assertSessionHasErrors('memberships');

        expect($fixture['vault']->refresh()->key_epoch)->toBe(1);
    });
});

describe('the epoch guard', function () {
    it('accepts only exactly the next epoch', function () {
        $fixture = rekeyFixture();

        foreach ([1, 3, 99] as $epoch) {
            $this->actingAs($fixture['owner'])
                ->post("/vaults/{$fixture['vault']->uuid}/rekey", rekeyPayload($fixture, ['key_epoch' => $epoch]))
                ->assertSessionHasErrors('key_epoch');
        }

        expect($fixture['vault']->refresh()->key_epoch)->toBe(1);
    });

    /**
     * Two owners rotating from the same stale page. The second must be refused
     * rather than overwriting the first — otherwise members would be left
     * holding keys sealed under a Vault Key that no longer wraps anything.
     */
    it('refuses a second rotation composed against the same epoch', function () {
        $fixture = rekeyFixture();

        $first = rekeyPayload($fixture);
        $second = rekeyPayload($fixture);

        $this->actingAs($fixture['owner'])
            ->post("/vaults/{$fixture['vault']->uuid}/rekey", $first)
            ->assertRedirect();

        $this->actingAs($fixture['owner'])
            ->post("/vaults/{$fixture['vault']->uuid}/rekey", $second)
            ->assertSessionHasErrors('key_epoch');

        expect($fixture['vault']->refresh()->key_epoch)->toBe(2)
            ->and($fixture['vault']->wrapped_item_key->base64)
            ->toBe(payloadString($first, 'vault_wrapped_item_key'));
    });
});

/**
 * A query-builder update writes columns without running the model's casts, and
 * the Ciphertext cast is where base64 is normalised and the size cap applied.
 * Easy to lose in a rewrite, invisible when lost — so it is asserted against the
 * raw column, since reading through the cast would canonicalise on the way out
 * and pass either way.
 */
it('canonicalises the wrapped keys it stores', function () {
    $fixture = rekeyFixture();

    $canonical = EnvelopeFixtures::envelope(48);
    $unpadded = rtrim($canonical, '=');

    expect($unpadded)->not->toBe($canonical);

    $payload = rekeyPayload($fixture);
    $items = itemsOf($payload);
    $target = $items[0]['uuid'];
    $items[0]['wrapped_item_key'] = $unpadded;
    $payload['items'] = $items;

    $this->actingAs($fixture['owner'])
        ->post("/vaults/{$fixture['vault']->uuid}/rekey", $payload)
        ->assertRedirect();

    $stored = DB::table('lockboxes')->where('uuid', $target)->value('wrapped_item_key')
        ?? DB::table('secrets')->where('uuid', $target)->value('wrapped_item_key');

    expect($stored)->toBe($canonical);
});
