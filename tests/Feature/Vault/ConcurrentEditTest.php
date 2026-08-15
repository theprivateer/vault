<?php

use App\Models\Lockbox;
use App\Models\Secret;
use App\Models\User;
use App\Models\Vault;
use Database\Factories\EnvelopeFixtures;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Inertia\Testing\AssertableInertia;

/**
 * Two people editing one secret.
 *
 * The server cannot merge two versions of a secret — they are ciphertext under
 * different item keys, and merging would mean reading them. So the only choice
 * is to detect the collision or to lose one silently, and a password that
 * disappears without anyone being told is the kind of bug discovered months
 * later, at the worst possible moment.
 *
 * `current_version` is the token. It is compared inside the `where` clause of
 * the update rather than read and then checked, because a read-then-write
 * leaves a window in which the other writer commits — on a concurrent edit,
 * which is the whole case being defended, that window is exactly when it
 * matters.
 */
function secretIn(Lockbox $lockbox): Secret
{
    return Secret::factory()->for($lockbox)->create();
}

/**
 * @param  array<string, mixed>  $overrides
 * @return array<string, mixed>
 */
function updatePayload(Secret $secret, array $overrides = []): array
{
    return [
        ...itemPayload(['payload_version' => 2]),
        ...archivePayload(),
        'expected_version' => $secret->current_version,
        ...$overrides,
    ];
}

/**
 * The payload an edit replaces, re-sealed as its own version (Phase 8).
 *
 * Required on every update, so it belongs in the shared helper rather than in
 * the history tests alone: an edit that does not append is refused, and a
 * fixture missing these fields fails validation and then quietly asserts
 * against a row nothing wrote.
 *
 * @return array<string, mixed>
 */
function archivePayload(): array
{
    return [
        'version_uuid' => (string) Str::uuid7(),
        'version_payload_ct' => EnvelopeFixtures::envelope(96),
        'version_wrapped_item_key' => EnvelopeFixtures::envelope(48),
        'version_payload_version' => 2,
    ];
}

it('accepts an update that carries the version it was composed against', function () {
    $user = User::factory()->create();
    $lockbox = Lockbox::factory()->for(Vault::factory()->ownedBy($user))->create();
    $secret = secretIn($lockbox);

    $payload = updatePayload($secret);

    $this->actingAs($user)->patch("/secrets/{$secret->uuid}", $payload)->assertRedirect();

    $secret->refresh();

    expect($secret->payload_ct->base64)->toBe(payloadString($payload, 'payload_ct'))
        ->and($secret->current_version)->toBe(2);
});

it('refuses a second write composed against a version that has moved on', function () {
    $user = User::factory()->create();
    $lockbox = Lockbox::factory()->for(Vault::factory()->ownedBy($user))->create();
    $secret = secretIn($lockbox);

    // Both tabs read version 1 and compose an edit against it.
    $first = updatePayload($secret);
    $second = updatePayload($secret);

    $this->actingAs($user)->patch("/secrets/{$secret->uuid}", $first)->assertRedirect();

    $this->actingAs($user)
        ->patch("/secrets/{$secret->uuid}", $second)
        ->assertSessionHasErrors('expected_version');

    // The first write survives intact. Neither version was silently merged,
    // and the loser is told rather than left believing it saved.
    expect($secret->refresh()->payload_ct->base64)->toBe(payloadString($first, 'payload_ct'))
        ->and($secret->current_version)->toBe(2);
});

it('lets the loser retry once it has the current version', function () {
    $user = User::factory()->create();
    $lockbox = Lockbox::factory()->for(Vault::factory()->ownedBy($user))->create();
    $secret = secretIn($lockbox);

    $this->actingAs($user)->patch("/secrets/{$secret->uuid}", updatePayload($secret))->assertRedirect();

    $retry = updatePayload($secret->refresh());

    $this->actingAs($user)->patch("/secrets/{$secret->uuid}", $retry)->assertRedirect();

    expect($secret->refresh()->payload_ct->base64)->toBe(payloadString($retry, 'payload_ct'))
        ->and($secret->current_version)->toBe(3);
});

it('requires the version rather than defaulting to last write wins', function () {
    $user = User::factory()->create();
    $lockbox = Lockbox::factory()->for(Vault::factory()->ownedBy($user))->create();
    $secret = secretIn($lockbox);

    $payload = itemPayload(['payload_version' => 2]);

    $this->actingAs($user)
        ->patch("/secrets/{$secret->uuid}", $payload)
        ->assertSessionHasErrors('expected_version');
});

/**
 * Not HTTP 409: Inertia reserves that status for its own asset-version
 * protocol and answers one with a hard page reload, which would throw away the
 * user's unsaved edit while telling them nothing about why.
 */
it('reports the conflict as a validation error, never as a 409', function () {
    $user = User::factory()->create();
    $lockbox = Lockbox::factory()->for(Vault::factory()->ownedBy($user))->create();
    $secret = secretIn($lockbox);

    $stale = updatePayload($secret);
    $this->actingAs($user)->patch("/secrets/{$secret->uuid}", updatePayload($secret));

    $response = $this->actingAs($user)->patch("/secrets/{$secret->uuid}", $stale);

    expect($response->getStatusCode())->not->toBe(409);
    $response->assertStatus(302);
});

/**
 * A guarded update is a query-builder update, which writes columns without
 * running the model's casts — and the Ciphertext cast is where base64 is
 * normalised and the size cap applied. Easy to lose, invisible when lost.
 *
 * Asserted against the raw column rather than the model attribute, because the
 * cast canonicalises on read as well as on write: going through
 * `$secret->payload_ct` would return a tidy value whatever is actually in the
 * database, and the test would pass with the guard removed.
 */
it('still canonicalises the ciphertext it stores', function () {
    $user = User::factory()->create();
    $lockbox = Lockbox::factory()->for(Vault::factory()->ownedBy($user))->create();
    $secret = secretIn($lockbox);

    $canonical = EnvelopeFixtures::envelope(96);
    $unpadded = rtrim($canonical, '=');

    // Without this the two strings are identical and the test below proves
    // nothing. 26 header-and-nonce bytes plus 96 is 122, which base64 pads.
    expect($unpadded)->not->toBe($canonical);

    $this->actingAs($user)
        ->patch("/secrets/{$secret->uuid}", updatePayload($secret, ['payload_ct' => $unpadded]))
        ->assertRedirect();

    $stored = DB::table('secrets')->where('id', $secret->getKey())->value('payload_ct');

    expect($stored)->toBe($canonical);
});

it('starts a new secret at version one', function () {
    $user = User::factory()->create();
    $lockbox = Lockbox::factory()->for(Vault::factory()->ownedBy($user))->create();

    $this->actingAs($user)
        ->post("/lockboxes/{$lockbox->uuid}/secrets", itemPayload(['payload_version' => 2]))
        ->assertRedirect();

    expect($lockbox->secrets()->sole()->current_version)->toBe(1);
});

it('sends the version to the client so it can be sent back', function () {
    $user = User::factory()->create();
    $vault = Vault::factory()->ownedBy($user)->create();
    $lockbox = Lockbox::factory()->for($vault)->create();
    secretIn($lockbox);

    $this->actingAs($user)
        ->get("/lockboxes/{$lockbox->uuid}")
        ->assertInertia(fn (AssertableInertia $page) => $page->where('secrets.0.version', 1));
});
