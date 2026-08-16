<?php

use App\Models\Lockbox;
use App\Models\Secret;
use App\Models\User;
use App\Models\Vault;
use Database\Factories\EnvelopeFixtures;
use Illuminate\Support\Str;

/**
 * Nothing submitted to this application comes back in the session (SR1).
 *
 * Laravel flashes the request body on a validation failure so a form can be
 * repopulated. Every write here carries ciphertext and wrapped key material, and
 * a concurrent-edit conflict *is* a validation failure by design — so the
 * routine case of two tabs on one secret was writing two payloads and two
 * wrapped Item Keys into the session store, encrypted under a key the server
 * holds. Found in the Phase 11.5 sweep; see docs/07-penetration-test.md F11.
 *
 * The guard is App\Http\Middleware\ForgetFlashedInput, which drops the flashed
 * input wholesale rather than naming fields. These tests are shaped the same
 * way: they assert the session carries *nothing*, so a field added next year is
 * covered without anybody remembering to come back here.
 */
/**
 * @return array<string, mixed>
 */
function conflictingUpdate(Secret $secret): array
{
    return [
        'uuid' => (string) Str::uuid7(),
        'payload_ct' => EnvelopeFixtures::envelope(96),
        'wrapped_item_key' => EnvelopeFixtures::envelope(48),
        'payload_version' => 2,
        'version_uuid' => (string) Str::uuid7(),
        'version_payload_ct' => EnvelopeFixtures::envelope(96),
        'version_wrapped_item_key' => EnvelopeFixtures::envelope(48),
        'version_payload_version' => 2,
        // Composed against a version that has already moved on.
        'expected_version' => $secret->current_version,
    ];
}

it('flashes nothing when two tabs collide on one secret', function () {
    $user = User::factory()->create();
    $lockbox = Lockbox::factory()->for(Vault::factory()->ownedBy($user))->create();
    $secret = Secret::factory()->for($lockbox)->create();

    $first = conflictingUpdate($secret);
    $second = conflictingUpdate($secret);

    $this->actingAs($user)->patch("/secrets/{$secret->uuid}", $first)->assertRedirect();

    $this->actingAs($user)
        ->patch("/secrets/{$secret->uuid}", $second)
        ->assertSessionHasErrors('expected_version');

    /*
     | The assertion that matters, and the reason it is written as "empty"
     | rather than as a list of forbidden keys: before the fix this held
     | payload_ct, wrapped_item_key, version_payload_ct and
     | version_wrapped_item_key, none of which any denylist named.
     */
    expect(session('_old_input', []))->toBe([]);
});

it('still reports the error itself, which is what the client needs', function () {
    $user = User::factory()->create();
    $lockbox = Lockbox::factory()->for(Vault::factory()->ownedBy($user))->create();
    $secret = Secret::factory()->for($lockbox)->create();

    // Forgetting the input must not forget the errors beside it: `errors` holds
    // messages rather than submitted values, and Inertia shares it every visit.
    $this->actingAs($user)
        ->patch("/secrets/{$secret->uuid}", [])
        ->assertSessionHasErrors(['payload_ct', 'expected_version']);

    expect(session('_old_input', []))->toBe([]);
});

it('keeps a credential out of the session when a request does not ask for json', function () {
    /*
     | The auth endpoints answer JSON to the real client, which never flashes.
     | That is a property of resources/js/lib/http.ts sending an Accept header,
     | not of the server — a request made any other way took the redirect path,
     | and recovery_auth_key was not on the old denylist either.
     */
    $this->post('/recover', ['email' => 'ada@example.com'])
        ->assertSessionHasErrors('recovery_auth_key');

    expect(session('_old_input', []))->toBe([]);
});

it('flashes nothing on a failed sign-in', function () {
    User::factory()->create(['email' => 'ada@example.com']);

    $this->post('/login', ['email' => 'ada@example.com', 'auth_key' => 'not-base64'])
        ->assertSessionHasErrors();

    expect(session('_old_input', []))->toBe([]);
});
