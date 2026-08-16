<?php

use App\Enums\AuditAction;
use App\Enums\VaultRole;
use App\Models\AuditEvent;
use App\Models\Lockbox;
use App\Models\Secret;
use App\Models\SecretVersion;
use App\Models\User;
use App\Models\Vault;
use App\Models\VaultFile;
use App\Rules\Envelope;
use Database\Factories\EnvelopeFixtures;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Str;
use Inertia\Testing\AssertableInertia;

/**
 * Moving payloads onto the current envelope version.
 *
 * Two things make this operation different from every other write here, and both
 * are what the tests are about.
 *
 * **It is not an edit.** The plaintext is identical, so nothing may behave as
 * though it changed: no version archived, `current_version` unmoved, `updated_at`
 * untouched, one audit entry rather than a run of them. A migration that looked
 * like somebody editing every secret in the vault would put a false history into
 * a table that cannot be corrected.
 *
 * **It is a data-loss bug without the compare-and-swap.** A tab that decrypted an
 * hour ago holds plaintext that may since have been edited elsewhere. Re-sealing
 * it writes the old value back under a fresh envelope, and every check in the
 * system passes — the ciphertext is well formed, correctly bound and freshly
 * sealed. Only the bytes it replaced know it is wrong.
 */

/**
 * A vault with one lockbox and one secret, all on the old envelope.
 *
 * An object rather than a list because four positional values read as four
 * chances to destructure them in the wrong order — and two of them are rows this
 * suite deliberately writes stale data over.
 */
final class ResealFixture
{
    public function __construct(
        public User $owner,
        public Vault $vault,
        public Lockbox $lockbox,
        public Secret $secret,
    ) {}
}

function resealable(): ResealFixture
{
    $owner = User::factory()->create();
    $vault = Vault::factory()->ownedBy($owner)->create();
    $lockbox = Lockbox::factory()->for($vault)->create();

    return new ResealFixture($owner, $vault, $lockbox, Secret::factory()->for($lockbox)->create());
}

/** A payload sealed at the version this build writes. */
function currentEnvelope(int $bodyBytes = 64): string
{
    return base64_encode(
        chr(Envelope::CURRENT_VERSION).chr(1).random_bytes(24 + max($bodyBytes, 17))
    );
}

/**
 * One re-seal entry for a row, digesting the ciphertext it currently holds.
 *
 * @param  array<string, mixed>  $overrides
 * @return array<string, mixed>
 */
function resealEntry(string $uuid, string $currentPayloadCt, array $overrides = []): array
{
    return [
        'uuid' => $uuid,
        'previous_digest' => base64_encode(sodium_crypto_generichash(
            (string) base64_decode($currentPayloadCt, true), '', 32
        )),
        'payload_ct' => currentEnvelope(),
        'wrapped_item_key' => currentEnvelope(48),
        'payload_version' => 2,
        ...$overrides,
    ];
}

describe('re-sealing', function () {
    it('replaces the payload and its item key, at the current version', function () {
        $fixture = resealable();
        $entry = resealEntry($fixture->secret->uuid, $fixture->secret->payload_ct->base64);

        $this->actingAs($fixture->owner)
            ->postJson("/vaults/{$fixture->vault->uuid}/reseal", ['items' => [$entry]])
            ->assertOk()
            ->assertJson(['applied' => 1, 'skipped' => 0]);

        $fixture->secret->refresh();

        expect($fixture->secret->payload_ct->base64)->toBe($entry['payload_ct'])
            ->and($fixture->secret->wrapped_item_key->base64)->toBe($entry['wrapped_item_key'])
            ->and($fixture->secret->payload_ct->envelopeVersion())->toBe(Envelope::CURRENT_VERSION);
    });

    it('reaches the vault, its lockboxes, its secrets and its files', function () {
        $fixture = resealable();
        $file = VaultFile::factory()->create(['lockbox_id' => $fixture->lockbox->getKey()]);

        $items = [
            resealEntry($fixture->vault->uuid, $fixture->vault->payload_ct->base64),
            resealEntry($fixture->lockbox->uuid, $fixture->lockbox->payload_ct->base64),
            resealEntry($fixture->secret->uuid, $fixture->secret->payload_ct->base64),
            resealEntry($file->uuid, $file->payload_ct->base64),
        ];

        $this->actingAs($fixture->owner)
            ->postJson("/vaults/{$fixture->vault->uuid}/reseal", ['items' => $items])
            ->assertOk()
            ->assertJson(['applied' => 4]);

        foreach ([$fixture->vault, $fixture->lockbox, $fixture->secret, $file] as $row) {
            expect($row->refresh()->payload_ct->envelopeVersion())->toBe(Envelope::CURRENT_VERSION);
        }
    });

    /*
     | The plaintext did not change, so nothing may say it did. A run of
     | `secret.updated` entries would put "somebody edited every secret in this
     | vault on a Tuesday" into a table that by design can never be corrected.
     */
    it('records one event for the batch, not one per row', function () {
        $fixture = resealable();

        $this->actingAs($fixture->owner)->postJson("/vaults/{$fixture->vault->uuid}/reseal", [
            'items' => [
                resealEntry($fixture->lockbox->uuid, $fixture->lockbox->payload_ct->base64),
                resealEntry($fixture->secret->uuid, $fixture->secret->payload_ct->base64),
            ],
        ])->assertOk();

        $event = AuditEvent::query()->where('action', AuditAction::VaultResealed)->sole();

        expect($event->subject_uuid)->toBe($fixture->vault->uuid)
            ->and($event->metadata)->toBe('{"count":2}')
            ->and(AuditEvent::query()->where('action', AuditAction::SecretUpdated)->count())->toBe(0);
    });

    it('archives no version and does not move the concurrency token', function () {
        $fixture = resealable();
        $before = $fixture->secret->current_version;

        $this->actingAs($fixture->owner)->postJson("/vaults/{$fixture->vault->uuid}/reseal", [
            'items' => [resealEntry($fixture->secret->uuid, $fixture->secret->payload_ct->base64)],
        ])->assertOk();

        expect($fixture->secret->refresh()->current_version)->toBe($before)
            ->and(SecretVersion::query()->count())->toBe(0);
    });

    /*
     | `updated_at` is what the interface shows as "last changed". Moving it for
     | a re-seal would tell everybody in the vault that a credential they rely on
     | was touched, which is both false and the kind of false that costs somebody
     | an afternoon.
     */
    it('leaves updated_at alone', function () {
        $fixture = resealable();
        $fixture->secret->forceFill(['updated_at' => now()->subYear()])->save();
        $before = $fixture->secret->refresh()->updated_at;

        $this->actingAs($fixture->owner)->postJson("/vaults/{$fixture->vault->uuid}/reseal", [
            'items' => [resealEntry($fixture->secret->uuid, $fixture->secret->payload_ct->base64)],
        ])->assertOk();

        expect($fixture->secret->refresh()->updated_at?->timestamp)->toBe($before?->timestamp);
    });
});

describe('the compare-and-swap', function () {
    /*
     | The test this whole endpoint exists to pass. Without it, a tab holding an
     | hour-old decrypt writes the old plaintext back under a fresh envelope and
     | every downstream check agrees: well formed, correctly bound, freshly
     | sealed, and wrong.
     */
    it('skips a row whose ciphertext moved since the client read it', function () {
        $fixture = resealable();

        // Built from what the client saw...
        $entry = resealEntry($fixture->secret->uuid, $fixture->secret->payload_ct->base64);

        // ...and then somebody edits the secret from another tab.
        $edited = currentEnvelope(96);
        $fixture->secret->forceFill(['payload_ct' => $edited])->save();

        $this->actingAs($fixture->owner)
            ->postJson("/vaults/{$fixture->vault->uuid}/reseal", ['items' => [$entry]])
            ->assertOk()
            ->assertJson(['applied' => 0, 'skipped' => 1]);

        expect($fixture->secret->refresh()->payload_ct->base64)->toBe($edited);
    });

    /*
     | Skipped rather than refused, because it is not an error: somebody wrote
     | the row, which puts it on the current envelope anyway. Failing the batch
     | would make a large vault impossible to migrate while anybody was using it.
     */
    it('applies the rest of the batch around a skipped row', function () {
        $fixture = resealable();

        $stale = resealEntry($fixture->secret->uuid, $fixture->secret->payload_ct->base64);
        $fixture->secret->forceFill(['payload_ct' => currentEnvelope(96)])->save();

        $this->actingAs($fixture->owner)
            ->postJson("/vaults/{$fixture->vault->uuid}/reseal", [
                'items' => [$stale, resealEntry($fixture->lockbox->uuid, $fixture->lockbox->payload_ct->base64)],
            ])
            ->assertOk()
            ->assertJson(['applied' => 1, 'skipped' => 1]);

        expect($fixture->lockbox->refresh()->payload_ct->envelopeVersion())->toBe(Envelope::CURRENT_VERSION);
    });

    it('counts only what it actually wrote', function () {
        $fixture = resealable();

        $stale = resealEntry($fixture->secret->uuid, $fixture->secret->payload_ct->base64);
        $fixture->secret->forceFill(['payload_ct' => currentEnvelope(96)])->save();

        $this->actingAs($fixture->owner)->postJson("/vaults/{$fixture->vault->uuid}/reseal", ['items' => [$stale]]);

        expect(AuditEvent::query()->where('action', AuditAction::VaultResealed)->sole()->metadata)
            ->toBe('{"count":0}');
    });
});

describe('what it refuses', function () {
    /*
     | A flat list of UUIDs spans four tables, so the resolution has to come from
     | the vault downwards. Letting a UUID from elsewhere through would be letting
     | the caller pick which row gets written.
     */
    it('refuses an item from another vault, and writes nothing', function () {
        $fixture = resealable();
        $elsewhere = resealable()->secret;

        $this->actingAs($fixture->owner)
            ->postJson("/vaults/{$fixture->vault->uuid}/reseal", [
                'items' => [resealEntry($elsewhere->uuid, $elsewhere->payload_ct->base64)],
            ])
            ->assertStatus(422)
            ->assertJsonValidationErrors('items');

        expect($elsewhere->refresh()->payload_ct->envelopeVersion())->toBe(1)
            ->and(AuditEvent::query()->where('action', AuditAction::VaultResealed)->count())->toBe(0);
    });

    it('refuses an unknown uuid', function () {
        $fixture = resealable();

        $this->actingAs($fixture->owner)
            ->postJson("/vaults/{$fixture->vault->uuid}/reseal", [
                'items' => [resealEntry((string) Str::uuid7(), currentEnvelope())],
            ])
            ->assertStatus(422)
            ->assertJsonValidationErrors('items');
    });

    it('refuses a payload that is not a plausible envelope', function () {
        $fixture = resealable();

        $this->actingAs($fixture->owner)
            ->postJson("/vaults/{$fixture->vault->uuid}/reseal", [
                'items' => [
                    resealEntry($fixture->secret->uuid, $fixture->secret->payload_ct->base64, [
                        'payload_ct' => base64_encode('nonsense'),
                    ]),
                ],
            ])
            ->assertStatus(422)
            ->assertJsonValidationErrors('items.0.payload_ct');
    });

    /*
     | A write ability rather than an administrator one: this changes no key and
     | no plaintext, and anybody who may edit a secret may re-seal it — editing
     | it would have done the same thing by a longer route. A viewer may not.
     */
    it('is closed to a viewer, and answers 404', function () {
        $fixture = resealable();
        $viewer = User::factory()->create();

        $fixture->vault->memberships()->create([
            'uuid' => (string) Str::uuid7(),
            'user_id' => $viewer->getKey(),
            'role' => VaultRole::Viewer,
            'wrapped_vault_key' => EnvelopeFixtures::sealedEnvelope(),
            'key_epoch' => $fixture->vault->key_epoch,
        ]);

        $this->actingAs($viewer)
            ->postJson("/vaults/{$fixture->vault->uuid}/reseal", [
                'items' => [resealEntry($fixture->secret->uuid, $fixture->secret->payload_ct->base64)],
            ])
            ->assertNotFound();
    });

    it('is closed to a stranger, and answers 404', function () {
        $fixture = resealable();

        $this->actingAs(User::factory()->create())
            ->postJson("/vaults/{$fixture->vault->uuid}/reseal", [
                'items' => [resealEntry($fixture->secret->uuid, $fixture->secret->payload_ct->base64)],
            ])
            ->assertNotFound();
    });
});

describe('the page and the health count', function () {
    it('serves every payload in the vault, files included', function () {
        $fixture = resealable();
        VaultFile::factory()->create(['lockbox_id' => $fixture->lockbox->getKey()]);

        $this->actingAs($fixture->owner)
            ->get("/vaults/{$fixture->vault->uuid}/reseal")
            ->assertOk()
            ->assertInertia(fn (AssertableInertia $page) => $page
                ->has('lockboxes', 1)
                ->has('secrets', 1)
                ->has('files', 1));
    });

    /*
     | Counted apart because a number that cannot reach zero is a number people
     | stop reading. An archived version is immutable by design — rewriting one
     | would be a rollback channel for a credential rotated *because* it leaked.
     */
    it('separates what a re-seal can move from what nothing can', function () {
        $fixture = resealable();

        SecretVersion::factory()->for($fixture->secret)->create(['version' => 1]);

        $this->actingAs($fixture->owner)->postJson("/vaults/{$fixture->vault->uuid}/reseal", [
            'items' => [
                resealEntry($fixture->vault->uuid, $fixture->vault->payload_ct->base64),
                resealEntry($fixture->secret->uuid, $fixture->secret->payload_ct->base64),
            ],
        ])->assertOk();

        Artisan::call('vault:health');
        $output = Artisan::output();

        // The lockbox is still on v1 and movable; the archived version is not.
        expect($output)->toContain('1 on the old version, movable by a re-seal')
            ->toContain('1 on the old version and immutable');
    });
});
