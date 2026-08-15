<?php

use App\Enums\AuditAction;
use App\Enums\VaultRole;
use App\Models\AuditEvent;
use App\Models\Lockbox;
use App\Models\Secret;
use App\Models\ShareLink;
use App\Models\User;
use App\Models\Vault;
use App\Support\ShareToken;
use Database\Factories\EnvelopeFixtures;
use Database\Factories\ShareLinkFactory;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Str;
use Inertia\Testing\AssertableInertia;

/**
 * One-time share links.
 *
 * Three properties carry this feature, and all three are exit criteria:
 *
 *  1. A link opens exactly as many times as it was allowed to, and then stops.
 *     The check and the count happen inside one locked transaction, because two
 *     simultaneous requests both seeing "0 of 1" is the entire failure mode of a
 *     one-time link.
 *  2. **Nothing the server writes down contains the token or the key.** That is
 *     the whole security argument, and it is the reason the token lives in the
 *     URL fragment and arrives in a request body rather than a path segment.
 *  3. The server cannot read what it is holding, which needs no test here
 *     because it holds no key — the leak canary covers the corollary.
 */

/**
 * A vault, a secret, and an owner who can share it.
 *
 * @return array{owner: User, vault: Vault, secret: Secret}
 */
function shareFixture(): array
{
    $owner = User::factory()->create();
    $vault = Vault::factory()->ownedBy($owner)->create();
    $lockbox = Lockbox::factory()->for($vault)->create();
    $secret = Secret::factory()->for($lockbox)->create();

    return compact('owner', 'vault', 'secret');
}

/**
 * @param  array<string, mixed>  $overrides
 * @return array<string, mixed>
 */
function linkPayload(string $token, array $overrides = []): array
{
    return [
        'uuid' => (string) Str::uuid7(),
        'token_hash' => ShareToken::hash($token),
        'payload_ct' => EnvelopeFixtures::envelope(200),
        'payload_version' => 2,
        'expires_in_hours' => 24,
        'max_views' => 1,
        ...$overrides,
    ];
}

describe('creating a link', function () {
    it('stores the hash of a token it never receives', function () {
        ['owner' => $owner, 'secret' => $secret] = shareFixture();

        $token = ShareLinkFactory::token();
        $payload = linkPayload($token);

        $this->actingAs($owner)->post("/secrets/{$secret->uuid}/links", $payload)->assertRedirect();

        $link = ShareLink::query()->sole();

        expect($link->token_hash)->toBe(ShareToken::hash($token))
            /*
             | The token itself appears nowhere. The creator's browser sent only
             | the hash, so the server never held a redeemable credential — not
             | even for the length of this request.
             */
            ->and($link->token_hash)->not->toContain($token)
            ->and($link->payload_ct->base64)->toBe(payloadString($payload, 'payload_ct'))
            ->and($link->created_by)->toBe($owner->getKey())
            ->and($link->secret_id)->toBe($secret->getKey());
    });

    it('refuses a link with no expiry, or one beyond the ceiling', function () {
        ['owner' => $owner, 'secret' => $secret] = shareFixture();

        $token = ShareLinkFactory::token();

        $this->actingAs($owner)
            ->post("/secrets/{$secret->uuid}/links", linkPayload($token, ['expires_in_hours' => 0]))
            ->assertSessionHasErrors('expires_in_hours');

        $this->actingAs($owner)
            ->post("/secrets/{$secret->uuid}/links", linkPayload($token, ['expires_in_hours' => 100_000]))
            ->assertSessionHasErrors('expires_in_hours');

        expect(ShareLink::query()->count())->toBe(0);
    });

    it('keeps a viewer from creating one', function () {
        ['vault' => $vault, 'secret' => $secret] = shareFixture();

        $viewer = User::factory()->create();
        $vault->memberships()->create([
            'uuid' => (string) Str::uuid7(),
            'user_id' => $viewer->getKey(),
            'role' => VaultRole::Viewer,
            'wrapped_vault_key' => EnvelopeFixtures::sealedEnvelope(),
            'key_epoch' => $vault->key_epoch,
        ]);

        $this->actingAs($viewer)
            ->post("/secrets/{$secret->uuid}/links", linkPayload(ShareLinkFactory::token()))
            ->assertNotFound();
    });

    it('records the link without recording what it holds', function () {
        ['owner' => $owner, 'secret' => $secret] = shareFixture();

        $this->actingAs($owner)->post(
            "/secrets/{$secret->uuid}/links",
            linkPayload(ShareLinkFactory::token(), ['max_views' => 3]),
        );

        $event = AuditEvent::query()->where('action', AuditAction::ShareLinkCreated)->sole();

        expect($event->decodedMetadata())->toBe(['max_views' => 3])
            ->and($event->subject_type)->toBe('sharelink');
    });
});

describe('opening a link', function () {
    it('serves the page with nothing in it', function () {
        /*
         | The whole point: the response carries no payload, because the token
         | is in a fragment this request never saw. There is nothing here for a
         | link preview to consume, either.
         */
        $this->get('/s')->assertInertia(
            fn (AssertableInertia $page) => $page->component('share/Open')->has('errors')
        );
    });

    it('hands over the payload once, and then 404s', function () {
        $token = ShareLinkFactory::token();
        $link = ShareLink::factory()->withToken($token)->create(['max_views' => 1]);

        $this->postJson('/s/reveal', ['token' => $token])
            ->assertOk()
            ->assertJson([
                'payloadCt' => $link->payload_ct->base64,
                'payloadVersion' => $link->payload_version,
                'viewsRemaining' => 0,
            ]);

        $this->postJson('/s/reveal', ['token' => $token])->assertNotFound();

        expect($link->refresh()->view_count)->toBe(1);
    });

    it('counts down a link allowed more than one opening', function () {
        $token = ShareLinkFactory::token();
        ShareLink::factory()->withToken($token)->create(['max_views' => 3]);

        foreach ([2, 1, 0] as $remaining) {
            $this->postJson('/s/reveal', ['token' => $token])
                ->assertOk()
                ->assertJson(['viewsRemaining' => $remaining]);
        }

        $this->postJson('/s/reveal', ['token' => $token])->assertNotFound();
    });

    /*
     | Every way of being unopenable answers identically. Distinguishing them
     | would tell a recipient whether somebody else had already opened their
     | link, which is a fact about another person's behaviour, and would tell a
     | holder of a guessed token that it once existed.
     */
    it('answers the same way however it is unopenable', function () {
        $expired = ShareLinkFactory::token();
        $revoked = ShareLinkFactory::token();
        $spent = ShareLinkFactory::token();

        ShareLink::factory()->withToken($expired)->expired()->create();
        ShareLink::factory()->withToken($revoked)->revoked()->create();
        ShareLink::factory()->withToken($spent)->exhausted()->create();

        foreach ([$expired, $revoked, $spent, ShareLinkFactory::token()] as $token) {
            $this->postJson('/s/reveal', ['token' => $token])->assertNotFound();
        }
    });

    it('refuses a token that is not the right shape', function () {
        $this->postJson('/s/reveal', ['token' => 'nope'])->assertStatus(422);
        $this->postJson('/s/reveal', [])->assertStatus(422);
    });

    it('records an opening with no actor, because there is none', function () {
        $token = ShareLinkFactory::token();
        ShareLink::factory()->withToken($token)->create(['max_views' => 2]);

        $this->postJson('/s/reveal', ['token' => $token])->assertOk();

        $event = AuditEvent::query()->where('action', AuditAction::ShareLinkViewed)->sole();

        expect($event->actor_uuid)->toBeNull()
            ->and($event->decodedMetadata())->toBe(['count' => 1, 'max_views' => 2]);
    });

    /*
     | A link outlives the secret it came from. Its payload is a copy under its
     | own key and owes nothing to that row, and a link that died because the
     | sender tidied up afterwards would be a confusing way to fail.
     */
    it('still opens after the secret it came from is deleted', function () {
        ['secret' => $secret] = shareFixture();

        $token = ShareLinkFactory::token();
        ShareLink::factory()->withToken($token)->create(['secret_id' => $secret->getKey()]);

        $secret->forceDelete();

        $this->postJson('/s/reveal', ['token' => $token])->assertOk();
    });
});

describe('the list of outstanding links', function () {
    /*
     | The page exists because a power nobody can find is not a power. Its
     | contents are derived from the same rule as the revoke ability, so there
     | is no second source of truth about who sees what.
     */
    it('shows the links you issued, with what the server knows about each', function () {
        ['owner' => $owner, 'secret' => $secret] = shareFixture();

        $link = ShareLink::factory()->create([
            'created_by' => $owner->getKey(),
            'secret_id' => $secret->getKey(),
            'max_views' => 3,
            'view_count' => 1,
        ]);

        $this->actingAs($owner)
            ->get('/account/links')
            ->assertInertia(fn (AssertableInertia $page) => $page
                ->component('share/Links')
                ->has('links', 1)
                ->where('links.0.uuid', $link->uuid)
                ->where('links.0.secretUuid', $secret->uuid)
                ->where('links.0.vaultUuid', $secret->lockbox->vault->uuid)
                ->where('links.0.viewCount', 1)
                ->where('links.0.maxViews', 3)
                ->where('links.0.mine', true)
                ->where('links.0.redeemable', true)
                // Everything needed to put a name to the row, and nothing that
                // would let the server do it.
                ->has('secrets', 1)
                ->has('vaults', 1)
                ->has('vaults.0.membership.wrappedVaultKey')
            );
    });

    /*
     | The other half of the ability. An owner can withdraw an editor's link, so
     | the owner has to be able to see it — otherwise the policy grants a power
     | that can only be exercised by someone who already knows the identifier.
     */
    it('shows an owner the links others issued into their vault', function () {
        ['owner' => $owner, 'vault' => $vault, 'secret' => $secret] = shareFixture();

        $editor = User::factory()->create();
        $vault->memberships()->create([
            'uuid' => (string) Str::uuid7(),
            'user_id' => $editor->getKey(),
            'role' => VaultRole::Editor,
            'wrapped_vault_key' => EnvelopeFixtures::sealedEnvelope(),
            'key_epoch' => $vault->key_epoch,
        ]);

        ShareLink::factory()->create([
            'created_by' => $editor->getKey(),
            'secret_id' => $secret->getKey(),
        ]);

        $this->actingAs($owner)
            ->get('/account/links')
            ->assertInertia(fn (AssertableInertia $page) => $page
                ->has('links', 1)
                ->where('links.0.mine', false)
                ->where('links.0.createdBy', $editor->display_name)
            );
    });

    it('does not show an editor the links of a vault they merely write to', function () {
        ['owner' => $owner, 'vault' => $vault, 'secret' => $secret] = shareFixture();

        $editor = User::factory()->create();
        $vault->memberships()->create([
            'uuid' => (string) Str::uuid7(),
            'user_id' => $editor->getKey(),
            'role' => VaultRole::Editor,
            'wrapped_vault_key' => EnvelopeFixtures::sealedEnvelope(),
            'key_epoch' => $vault->key_epoch,
        ]);

        ShareLink::factory()->create([
            'created_by' => $owner->getKey(),
            'secret_id' => $secret->getKey(),
        ]);

        $this->actingAs($editor)->get('/account/links')->assertInertia(
            fn (AssertableInertia $page) => $page->has('links', 0)
        );
    });

    it('shows nothing of somebody else’s links', function () {
        ['secret' => $secret] = shareFixture();

        ShareLink::factory()->create(['secret_id' => $secret->getKey()]);

        $this->actingAs(User::factory()->create())
            ->get('/account/links')
            ->assertInertia(fn (AssertableInertia $page) => $page->has('links', 0)->has('vaults', 0));
    });

    /*
     | Finished links stay listed until the hourly sweep takes them. "This was
     | opened twice and then expired" is most of why somebody opens this page.
     */
    it('keeps showing links that can no longer be opened', function () {
        ['owner' => $owner, 'secret' => $secret] = shareFixture();

        ShareLink::factory()->expired()->create([
            'created_by' => $owner->getKey(),
            'secret_id' => $secret->getKey(),
        ]);

        $this->actingAs($owner)
            ->get('/account/links')
            ->assertInertia(fn (AssertableInertia $page) => $page
                ->has('links', 1)
                ->where('links.0.redeemable', false)
            );
    });

    /*
     | A link outlives its secret, so the row has to survive having nothing to
     | point at — and the page must be able to tell that apart from a vault it
     | simply cannot read.
     */
    it('lists a link whose secret has been deleted, with nothing to name it', function () {
        ['owner' => $owner, 'secret' => $secret] = shareFixture();

        ShareLink::factory()->create([
            'created_by' => $owner->getKey(),
            'secret_id' => $secret->getKey(),
        ]);

        $secret->forceDelete();

        $this->actingAs($owner)
            ->get('/account/links')
            ->assertInertia(fn (AssertableInertia $page) => $page
                ->has('links', 1)
                ->where('links.0.secretUuid', null)
                ->where('links.0.vaultUuid', null)
                ->has('vaults', 0)
            );
    });

    it('never puts the token or the payload in the list', function () {
        ['owner' => $owner, 'secret' => $secret] = shareFixture();

        $link = ShareLink::factory()->create([
            'created_by' => $owner->getKey(),
            'secret_id' => $secret->getKey(),
        ]);

        $response = $this->actingAs($owner)->get('/account/links');

        /*
         | The page renders metadata, and a payload here would be a copy of the
         | secret handed to a page that has no business with it — harmless while
         | the key is elsewhere, and exactly the sort of thing that stops being
         | harmless later.
         */
        expect($response->getContent())->not->toContain($link->token_hash)
            ->and($response->getContent())->not->toContain($link->payload_ct->base64);
    });
});

describe('withdrawing a link', function () {
    it('lets the creator end one early', function () {
        ['owner' => $owner, 'secret' => $secret] = shareFixture();

        $token = ShareLinkFactory::token();
        $link = ShareLink::factory()->withToken($token)->create([
            'created_by' => $owner->getKey(),
            'secret_id' => $secret->getKey(),
        ]);

        $this->actingAs($owner)->delete("/links/{$link->uuid}")->assertRedirect();

        expect($link->refresh()->revoked_at)->not->toBeNull();

        $this->postJson('/s/reveal', ['token' => $token])->assertNotFound();
    });

    /*
     | The case this ability exists for: an editor shared something they should
     | not have, and waiting for the expiry is not a remedy.
     */
    it('lets a vault owner withdraw a link an editor created', function () {
        ['owner' => $owner, 'vault' => $vault, 'secret' => $secret] = shareFixture();

        $editor = User::factory()->create();
        $vault->memberships()->create([
            'uuid' => (string) Str::uuid7(),
            'user_id' => $editor->getKey(),
            'role' => VaultRole::Editor,
            'wrapped_vault_key' => EnvelopeFixtures::sealedEnvelope(),
            'key_epoch' => $vault->key_epoch,
        ]);

        $link = ShareLink::factory()->create([
            'created_by' => $editor->getKey(),
            'secret_id' => $secret->getKey(),
        ]);

        $this->actingAs($owner)->delete("/links/{$link->uuid}")->assertRedirect();

        expect($link->refresh()->revoked_at)->not->toBeNull();
    });

    it('hides a link from someone with nothing to do with it', function () {
        ['secret' => $secret] = shareFixture();

        $link = ShareLink::factory()->create(['secret_id' => $secret->getKey()]);

        $this->actingAs(User::factory()->create())
            ->delete("/links/{$link->uuid}")
            ->assertNotFound();

        expect($link->refresh()->revoked_at)->toBeNull();
    });
});

describe('the sweep', function () {
    it('removes everything that can no longer be opened, and keeps what can', function () {
        ShareLink::factory()->expired()->create();
        ShareLink::factory()->revoked()->create();
        ShareLink::factory()->exhausted()->create();
        $live = ShareLink::factory()->create();

        expect(pruneLinks())->toBe(0)
            ->and(ShareLink::query()->pluck('uuid')->all())->toBe([$live->uuid]);
    });

    it('changes nothing on a dry run', function () {
        ShareLink::factory()->expired()->create();

        expect(pruneLinks(['--dry-run' => true]))->toBe(0)
            ->and(ShareLink::query()->count())->toBe(1)
            ->and(AuditEvent::query()->where('action', AuditAction::ShareLinkExpired)->count())->toBe(0);
    });

    it('records how much of a link was used before it went', function () {
        ShareLink::factory()->create([
            'expires_at' => now()->subHour(),
            'view_count' => 0,
            'max_views' => 2,
        ]);

        pruneLinks();

        $event = AuditEvent::query()->where('action', AuditAction::ShareLinkExpired)->sole();

        // Zero of two: expired unopened, which reads very differently from a
        // link that was used and then aged out.
        expect($event->decodedMetadata())->toBe(['count' => 0, 'max_views' => 2])
            ->and($event->actor_uuid)->toBeNull();
    });
});

/**
 * The exit criterion, and the entire reason the token is in the fragment.
 *
 * A token in a path segment is written to every access log in front of the
 * application, in the clear, by default. Nothing in this application could
 * prevent that — which is why the design puts it in a request body instead, and
 * why this test sweeps for it rather than asserting a policy.
 */
describe('what the server writes down', function () {
    it('never records the token or the link key anywhere it controls', function () {
        ['owner' => $owner, 'secret' => $secret] = shareFixture();

        $token = ShareLinkFactory::token();

        // A stand-in for the link key, which never reaches the server at all —
        // it is in the fragment. Sent here the way a careless client would, so
        // the sweep has something to find if anything ever persists raw input.
        $linkKey = 'LINKKEY-'.Str::random(32);

        $this->actingAs($owner)->post(
            "/secrets/{$secret->uuid}/links",
            [...linkPayload($token), 'key' => $linkKey, 'fragment' => $linkKey],
        )->assertRedirect();

        $this->postJson('/s/reveal', ['token' => $token])->assertOk();

        $haystack = shareHaystack();

        // Not vacuous: the row really was written and is in what is being swept.
        expect(ShareLink::query()->count())->toBe(1)
            ->and(implode('', $haystack))->toContain(ShareToken::hash($token));

        foreach ($haystack as $where => $contents) {
            expect(str_contains($contents, $token))->toBeFalse(
                "The share token reached {$where}, where any access log would also have it."
            );

            expect(str_contains($contents, $linkKey))->toBeFalse(
                "The link key reached {$where}, and it is meant never to leave the browser."
            );
        }
    });
});

/**
 * Every table and every log file, as one searchable map.
 *
 * Keyed by where each haystack came from, so a failure names the place rather
 * than saying only that something matched somewhere.
 *
 * @return array<string, string>
 */
function shareHaystack(): array
{
    $haystack = [];

    foreach (['share_links', 'audit_events', 'secrets', 'sessions'] as $table) {
        /*
         | JSON_UNESCAPED_SLASHES matters here rather than being tidiness. The
         | default escapes `/` as `\/`, and base64 is full of slashes — so a
         | sweep over the escaped form would silently fail to match anything
         | containing one, which is most values. A leak canary that cannot find
         | what it is looking for is worse than no canary.
         */
        $haystack["the {$table} table"] = json_encode(
            DB::table($table)->get()->toArray(),
            JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES,
        );
    }

    foreach (File::glob(storage_path('logs/*.log')) as $path) {
        if (! is_string($path)) {
            continue;
        }

        $haystack["the log {$path}"] = File::get($path);
    }

    return $haystack;
}

/**
 * @param  array<string, mixed>  $options
 */
function pruneLinks(array $options = []): int
{
    return Artisan::call('vault:links-prune', $options);
}
