<?php

use App\Models\Lockbox;
use App\Models\User;
use App\Models\Vault;
use Database\Factories\EnvelopeFixtures;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;

/**
 * SR1, the leak canary.
 *
 * A secret with a unique sentinel value goes in through the real endpoints, and
 * then every place the server could conceivably have written it is swept for
 * that sentinel: every column of every table, every log file, the cache store,
 * the queue tables, and the storage disk.
 *
 * This is the single highest-value test here, because it catches the mistake
 * that review does not: someone adds a searchable `name` column "just for the
 * index", or a debug log line with the request body, and every other test still
 * passes. It runs on every commit.
 *
 * Two sentinels, for two different mistakes:
 *
 *   - The **encrypted** one is inside a real XChaCha20-Poly1305 envelope, built
 *     with ext-sodium exactly as the browser would build it. If it ever appears
 *     in the clear, something decrypted it, which the server has no key to do.
 *   - The **plaintext** one is posted in every field of every request, as a
 *     buggy or hostile client might. If it appears anywhere durable, some code
 *     path is persisting or logging raw request input.
 */

/** Framework bookkeeping with no relationship to user content. */
const CANARY_IGNORED_TABLES = ['migrations'];

function canarySentinel(string $label): string
{
    return "CANARY-{$label}-".Str::random(24);
}

/**
 * Seals a plaintext exactly as resources/js/crypto/envelope.ts does.
 *
 * Independently implemented and pinned byte-for-byte against the browser core
 * by tests/Feature/CryptoInteropTest.php, so this is a faithful stand-in for a
 * real client rather than an approximation.
 */
function canaryEnvelope(string $plaintext): string
{
    $key = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES);
    $nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);

    // [ver:1][alg:1][nonce:24][ciphertext + tag]
    return base64_encode(
        chr(1).chr(1).$nonce.sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
            $plaintext,
            'vault.v1',
            $nonce,
            $key
        )
    );
}

/**
 * Everything durable the application controls, as one searchable haystack.
 *
 * @return array<string, string>
 */
function canaryHaystack(): array
{
    $haystack = [];

    foreach (Schema::getTableListing(schemaQualified: false) as $table) {
        if (! is_string($table) || in_array($table, CANARY_IGNORED_TABLES, true)) {
            continue;
        }

        $rows = DB::table($table)->get()->map(fn (object $row): array => (array) $row)->all();

        // Unescaped slashes, so base64 in a column appears verbatim rather
        // than as JSON's escaped form and slips past the search.
        $haystack["table:{$table}"] = json_encode($rows, JSON_UNESCAPED_SLASHES) ?: '';
    }

    foreach (File::allFiles(storage_path('logs')) as $log) {
        $haystack["log:{$log->getFilename()}"] = $log->getContents();
    }

    foreach (Storage::disk('local')->allFiles() as $path) {
        $haystack["storage:{$path}"] = (string) Storage::disk('local')->get($path);
    }

    /*
     | The cache is a table under the configured driver, read directly rather
     | than through the facade so that whatever the test environment sets
     | CACHE_STORE to, the durable store is still swept. A move to Redis would
     | need this extended, and the self-test below is what would notice.
     */
    $haystack['cache'] = json_encode(DB::table('cache')->get()->all(), JSON_UNESCAPED_SLASHES) ?: '';

    return $haystack;
}

/**
 * @param  array<string, string>  $haystack
 */
function assertCanaryAbsent(array $haystack, string $sentinel, string $because): void
{
    $found = array_keys(array_filter(
        $haystack,
        fn (string $contents): bool => str_contains($contents, $sentinel)
    ));

    expect($found)->toBe([], "{$because} — the sentinel appeared in: ".implode(', ', $found));
}

it('never writes a secret\'s plaintext anywhere it controls', function () {
    $encrypted = canarySentinel('ENCRYPTED');
    $plaintext = canarySentinel('PLAINTEXT');

    // The sentinel deliberately goes nowhere the schema expects it. Email and
    // display name are documented plaintext (docs/04-data-model.md) and putting
    // it there would make the canary find its own fixture.
    $user = User::factory()->create(['handle' => 'canary']);
    $vault = Vault::factory()->ownedBy($user)->create();
    $lockbox = Lockbox::factory()->for($vault)->create();

    $payloadCt = canaryEnvelope(json_encode([
        'type' => 'password',
        'key' => 'production database',
        'value' => $encrypted,
    ]) ?: '');

    /*
     | The plaintext sentinel rides along in fields the server does not use, the
     | way a buggy client would send them. They must be discarded, not stored.
     */
    $this->actingAs($user)
        ->post("/lockboxes/{$lockbox->uuid}/secrets", [
            'uuid' => (string) Str::uuid7(),
            'payload_ct' => $payloadCt,
            'wrapped_item_key' => EnvelopeFixtures::envelope(48),
            'payload_version' => 1,
            'name' => $plaintext,
            'value' => $plaintext,
            'description' => $plaintext,
            'notes' => $plaintext,
        ])
        ->assertRedirect();

    $haystack = canaryHaystack();

    /*
     | Guards against a vacuous pass. If the write silently failed there would
     | be nothing to find, and the sweep below would be green for the worst
     | possible reason.
     */
    expect($lockbox->secrets()->count())->toBe(1)
        ->and(implode('', $haystack))->toContain($payloadCt);

    assertCanaryAbsent(
        $haystack,
        $encrypted,
        'The server decrypted a payload, which it has no key to do'
    );

    assertCanaryAbsent(
        $haystack,
        $plaintext,
        'Raw request input was persisted or logged'
    );
});

/*
 | The same sweep over a file attachment, which is the one thing that leaves the
 | database entirely.
 |
 | 2017 wrote uploads to disk under a name derived from the original and kept
 | `original_name`, `file_type` and `extension` as plaintext columns — a
 | directory listing was a table of contents. This asserts that neither the name
 | nor the body survives anywhere the server controls, and that a client sending
 | them as fields cannot talk the server into keeping them.
 */
it('never writes a file\'s name or contents anywhere it controls', function () {
    $filename = canarySentinel('FILENAME');
    $contents = canarySentinel('FILEBODY');

    /*
     | Faked so the sweep sees exactly what this test wrote and nothing else,
     | and so a test does not leave a chunk in a developer's storage directory.
     | The other cases here deliberately sweep the real disk instead, where a
     | stray write from anywhere in the application would show up.
     */
    Storage::fake('local');

    $user = User::factory()->create(['handle' => 'file-canary']);
    $vault = Vault::factory()->ownedBy($user)->create();
    $lockbox = Lockbox::factory()->for($vault)->create();
    $uuid = (string) Str::uuid7();

    // The manifest, holding the filename, exactly as a browser would seal it.
    $payloadCt = canaryEnvelope(json_encode([
        'filename' => $filename,
        'mime' => 'text/plain',
        'chunkCount' => 1,
    ]) ?: '');

    $this->actingAs($user)
        ->post("/lockboxes/{$lockbox->uuid}/files", [
            'uuid' => $uuid,
            'payload_ct' => $payloadCt,
            'wrapped_item_key' => EnvelopeFixtures::envelope(48),
            'payload_version' => 2,
            'chunk_count' => 1,
            // Sent the way a careless client would. Must be discarded.
            'filename' => $filename,
            'original_name' => $filename,
            'extension' => 'txt',
            'mime' => 'text/plain',
        ])
        ->assertRedirect();

    // A chunk whose *plaintext* holds the sentinel. Encrypted here, because a
    // real one would be, and the point is that the ciphertext is all that lands.
    $chunk = chr(1).chr(2).sodium_crypto_aead_aes256gcm_encrypt(
        $contents,
        'vault.v1',
        random_bytes(12),
        random_bytes(32)
    );

    $this->actingAs($user)
        ->call('PUT', "/files/{$uuid}/chunks/0", content: $chunk)
        ->assertOk();

    $haystack = canaryHaystack();

    // Not vacuous: the chunk really did land on the disk being swept.
    expect(Storage::disk('local')->allFiles())->toHaveCount(1)
        ->and(implode('', $haystack))->toContain($payloadCt);

    assertCanaryAbsent($haystack, $filename, 'A filename reached a column, a log or the disk');
    assertCanaryAbsent($haystack, $contents, 'A file body was stored or logged in the clear');

    /*
     | And the path itself says nothing. An extension or a name-derived
     | directory would leak the same information as the old column did, without
     | any row to point at.
     */
    foreach (Storage::disk('local')->allFiles() as $path) {
        expect($path)->not->toContain($filename)
            ->and(pathinfo($path, PATHINFO_EXTENSION))->toBe('');
    }
});

it('leaks nothing through a request that fails validation', function () {
    $plaintext = canarySentinel('REJECTED');

    $user = User::factory()->create();
    $vault = Vault::factory()->ownedBy($user)->create();

    // Rejected requests are the easy place to forget: an exception handler that
    // logs the body would put the whole payload straight into a log file.
    $this->actingAs($user)
        ->post("/vaults/{$vault->uuid}/lockboxes", [
            'uuid' => 'not-a-uuid',
            'payload_ct' => $plaintext,
            'wrapped_item_key' => $plaintext,
            'payload_version' => 1,
        ])
        ->assertSessionHasErrors();

    assertCanaryAbsent(
        canaryHaystack(),
        $plaintext,
        'A rejected request left its body somewhere durable'
    );
});

it('sweeps the places it claims to sweep', function () {
    // The canary is only worth what its haystack covers. This asserts the
    // sweep actually reaches a table, a log and the cache — so a silently
    // empty haystack cannot make the tests above pass.
    $marker = canarySentinel('SELFTEST');

    File::put(storage_path('logs/canary-selftest.log'), $marker);
    // The database store explicitly: the test environment may cache in an
    // array, and this is asserting the sweep reaches the durable table.
    Cache::store('database')->put('canary-selftest', $marker, 60);
    User::factory()->create(['display_name' => $marker]);

    $haystack = canaryHaystack();

    try {
        expect(array_keys(array_filter(
            $haystack,
            fn (string $contents): bool => str_contains($contents, $marker)
        )))->toContain('table:users', 'log:canary-selftest.log', 'cache');
    } finally {
        File::delete(storage_path('logs/canary-selftest.log'));
    }
});
