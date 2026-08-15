<?php

use App\Enums\AuditAction;
use App\Enums\VaultRole;
use App\Models\AuditEvent;
use App\Models\Lockbox;
use App\Models\Secret;
use App\Models\User;
use App\Models\Vault;
use App\Support\AuditChain;
use App\Support\AuditStatement;
use Database\Factories\EnvelopeFixtures;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

/**
 * The events the browser reports, and the signature that makes them worth more
 * than the server's word.
 *
 * Every other entry in the log is the server's account of something it watched.
 * These two — a vault unlocked, a secret revealed — are the only ones it did not
 * witness, which makes them the only ones it could invent freely. The signature
 * is what removes that, and it is the reason this file exists separately from
 * the chain tests: the chain proves nothing was *changed*, and only a signature
 * proves something was not *fabricated*.
 *
 * Real Ed25519 throughout. `ext-sodium` here stands in for the browser's
 * `@noble/curves`, and the two are pinned against each other byte-for-byte by
 * tests/Feature/CryptoInteropTest.php.
 */

/**
 * An account with a real signing key, and the secret key to sign with.
 *
 * @return array{User, non-empty-string}
 */
function signingUser(): array
{
    $keypair = sodium_crypto_sign_keypair();
    $user = User::factory()->create();

    $user->identity()->create([
        'x25519_public_key' => base64_encode(random_bytes(32)),
        'ed25519_public_key' => base64_encode(sodium_crypto_sign_publickey($keypair)),
        'x25519_private_key_ct' => EnvelopeFixtures::envelope(48),
        'ed25519_private_key_ct' => EnvelopeFixtures::envelope(80),
        'self_signature' => base64_encode(random_bytes(64)),
        'fingerprint' => base64_encode(random_bytes(32)),
    ]);

    return [$user, sodium_crypto_sign_secretkey($keypair)];
}

/** The canonical statement the browser builds, byte-for-byte. */
function statementFor(string $action, string $subjectUuid, ?string $at = null): string
{
    return json_encode([
        'v' => AuditStatement::VERSION,
        'action' => $action,
        'subjectUuid' => $subjectUuid,
        'at' => $at ?? now()->utc()->format('Y-m-d\TH:i:s\Z'),
    ], JSON_UNESCAPED_SLASHES) ?: '';
}

/** @param  non-empty-string  $secretKey */
function signStatement(string $payload, string $secretKey): string
{
    return base64_encode(sodium_crypto_sign_detached(AuditStatement::signedBytes($payload), $secretKey));
}

/**
 * A vault the user owns, with a lockbox and a secret in it.
 *
 * @return array{Vault, Secret}
 */
function ownedTree(User $user): array
{
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

    return [$vault, Secret::factory()->create(['lockbox_id' => $lockbox->getKey()])];
}

describe('reporting', function () {
    it('records a signed reveal, with the exact bytes that were signed', function () {
        [$user, $secretKey] = signingUser();
        [, $secret] = ownedTree($user);

        $payload = statementFor('secret.revealed', $secret->uuid);

        $this->actingAs($user)
            ->postJson('/audit', [
                'action' => 'secret.revealed',
                'subject_uuid' => $secret->uuid,
                'payload' => $payload,
                'signature' => signStatement($payload, $secretKey),
            ])
            ->assertOk();

        $event = AuditEvent::query()->sole();

        expect($event->action)->toBe(AuditAction::SecretRevealed)
            ->and($event->subject_uuid)->toBe($secret->uuid)
            ->and($event->actor_uuid)->toBe($user->uuid)
            /*
             | Stored verbatim, never rebuilt from columns. A signature verifies
             | over bytes, and re-serialising them at verification time would
             | invalidate every signature the day the format changed — the same
             | reasoning as `grant_payload`.
             */
            ->and($event->signed_payload)->toBe($payload);
    });

    it('records a signed unlock against the vault', function () {
        [$user, $secretKey] = signingUser();
        [$vault] = ownedTree($user);

        $payload = statementFor('vault.unlocked', $vault->uuid);

        $this->actingAs($user)
            ->postJson('/audit', [
                'action' => 'vault.unlocked',
                'subject_uuid' => $vault->uuid,
                'payload' => $payload,
                'signature' => signStatement($payload, $secretKey),
            ])
            ->assertOk();

        expect(AuditEvent::query()->sole()->action)->toBe(AuditAction::VaultUnlocked);
    });

    it('accepts only the actions the server cannot observe for itself', function () {
        [$user, $secretKey] = signingUser();
        [$vault] = ownedTree($user);

        // A server-observed action. There is no reason to take the client's
        // word for something the server watched happen, and every reason not to.
        $payload = statementFor('vault.deleted', $vault->uuid);

        $this->actingAs($user)
            ->postJson('/audit', [
                'action' => 'vault.deleted',
                'subject_uuid' => $vault->uuid,
                'payload' => $payload,
                'signature' => signStatement($payload, $secretKey),
            ])
            ->assertStatus(422)
            ->assertJsonValidationErrors('action');
    });
});

describe('refusing', function () {
    it('refuses a signature that does not verify', function () {
        [$user] = signingUser();
        [, $secret] = ownedTree($user);

        // Signed by somebody else's key, which is to say: forged.
        [, $stranger] = signingUser();
        $payload = statementFor('secret.revealed', $secret->uuid);

        $this->actingAs($user)
            ->postJson('/audit', [
                'action' => 'secret.revealed',
                'subject_uuid' => $secret->uuid,
                'payload' => $payload,
                'signature' => signStatement($payload, $stranger),
            ])
            ->assertStatus(422)
            ->assertJsonValidationErrors('signature');

        expect(AuditEvent::query()->count())->toBe(0);
    });

    /*
     | The comparison, not the signature. A valid signature proves this user
     | once signed *some* statement; matching the signed fields against the
     | event being recorded is what turns that into evidence about *this* event.
     | Without it, a genuine signature over one secret could be stapled to a
     | request naming another.
     */
    it('refuses a genuine signature over a different subject', function () {
        [$user, $secretKey] = signingUser();
        [, $first] = ownedTree($user);
        [, $second] = ownedTree($user);

        $payload = statementFor('secret.revealed', $first->uuid);

        $this->actingAs($user)
            ->postJson('/audit', [
                'action' => 'secret.revealed',
                'subject_uuid' => $second->uuid,
                'payload' => $payload,
                'signature' => signStatement($payload, $secretKey),
            ])
            ->assertStatus(422)
            ->assertJsonValidationErrors('signature');
    });

    /*
     | Replay. A captured request posted back indefinitely would bury real
     | entries under plausible noise, in a table that by design can never be
     | cleaned up.
     */
    it('refuses a statement dated outside the clock-skew window', function () {
        [$user, $secretKey] = signingUser();
        [, $secret] = ownedTree($user);

        $payload = statementFor(
            'secret.revealed',
            $secret->uuid,
            now()->subHour()->utc()->format('Y-m-d\TH:i:s\Z'),
        );

        $this->actingAs($user)
            ->postJson('/audit', [
                'action' => 'secret.revealed',
                'subject_uuid' => $secret->uuid,
                'payload' => $payload,
                'signature' => signStatement($payload, $secretKey),
            ])
            ->assertStatus(422)
            ->assertJsonValidationErrors('signature');
    });

    /*
     | Log poisoning. Without a policy check, any authenticated account could
     | write somebody else's UUID into a permanent record by claiming to have
     | revealed their secret.
     */
    it('refuses to report an event about a record the account cannot reach', function () {
        [$user, $secretKey] = signingUser();
        [, $mine] = ownedTree($user);

        $stranger = User::factory()->create();
        [, $theirs] = ownedTree($stranger);

        $payload = statementFor('secret.revealed', $theirs->uuid);

        $this->actingAs($user)
            ->postJson('/audit', [
                'action' => 'secret.revealed',
                'subject_uuid' => $theirs->uuid,
                'payload' => $payload,
                'signature' => signStatement($payload, $secretKey),
            ])
            ->assertStatus(422)
            ->assertJsonValidationErrors('subject_uuid');

        expect($mine->uuid)->not->toBe($theirs->uuid)
            ->and(AuditEvent::query()->count())->toBe(0);
    });

    it('refuses an account with no signing key', function () {
        $user = User::factory()->create();
        [, $secret] = ownedTree($user);

        $payload = statementFor('secret.revealed', $secret->uuid);

        $this->actingAs($user)
            ->postJson('/audit', [
                'action' => 'secret.revealed',
                'subject_uuid' => $secret->uuid,
                'payload' => $payload,
                'signature' => base64_encode(random_bytes(64)),
            ])
            ->assertStatus(422)
            ->assertJsonValidationErrors('signature');
    });
});

describe('verification', function () {
    it('re-checks every signature when the chain is walked', function () {
        [$user, $secretKey] = signingUser();
        [, $secret] = ownedTree($user);

        $payload = statementFor('secret.revealed', $secret->uuid);

        $this->actingAs($user)
            ->postJson('/audit', [
                'action' => 'secret.revealed',
                'subject_uuid' => $secret->uuid,
                'payload' => $payload,
                'signature' => signStatement($payload, $secretKey),
            ])
            ->assertOk();

        expect(Artisan::call('vault:audit-verify'))->toBe(0)
            ->and(Artisan::output())->toContain('1 of them signed');
    });

    /*
     | The case the whole signing design exists for: a server that decides,
     | after the fact, to add an event the user never reported. It can compute
     | every hash in the chain, and it cannot produce this signature.
     */
    it('catches an entry the server fabricated after the fact', function () {
        [$user, $secretKey] = signingUser();
        [, $secret] = ownedTree($user);

        $payload = statementFor('secret.revealed', $secret->uuid);

        $this->actingAs($user)
            ->postJson('/audit', [
                'action' => 'secret.revealed',
                'subject_uuid' => $secret->uuid,
                'payload' => $payload,
                'signature' => signStatement($payload, $secretKey),
            ])
            ->assertOk();

        // Rewriting the signature to something the key never produced, and
        // recomputing the chain from that row so the hashes still line up —
        // which is exactly what a compromised server is able to do.
        $event = AuditEvent::query()->sole();

        DB::table('audit_events')
            ->where('seq', $event->seq)
            ->update(['actor_signature' => base64_encode(random_bytes(64))]);

        $fresh = AuditEvent::query()->sole();
        $recomputed = base64_encode(AuditChain::hash(
            (string) base64_decode($fresh->prev_hash, true),
            $fresh
        ));

        DB::table('audit_events')
            ->where('seq', $event->seq)
            ->update(['hash' => $recomputed]);

        DB::table('audit_chain')
            ->where('id', 1)
            ->update(['head_hash' => $recomputed]);

        // The chain now verifies perfectly. The signature does not.
        expect(Artisan::call('vault:audit-verify'))->toBe(1)
            ->and(Artisan::output())->toContain('signature does not verify');
    });
});
