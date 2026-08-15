<?php

use App\Enums\VaultRole;
use App\Models\Lockbox;
use App\Models\User;
use App\Models\Vault;
use App\Models\VaultFile;
use Database\Factories\EnvelopeFixtures;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;

/**
 * File attachments, from the server's side of the boundary.
 *
 * Everything here is about a server that cannot read what it is storing: it
 * checks shapes and sizes, counts bytes for a quota, tracks which chunks have
 * arrived, and refuses to name a file on disk. The cryptographic properties —
 * that a reordered or truncated file fails to decrypt — belong to the browser
 * and are proved in resources/js/crypto/chunks.test.ts, because they are
 * properties the tag enforces and this server holds no key to check.
 */
beforeEach(function () {
    Storage::fake('local');
});

/** A correctly shaped encrypted chunk: version 1, AES-256-GCM, then noise. */
function chunkBytes(int $bodyBytes = 64): string
{
    return chr(1).chr(2).random_bytes(max($bodyBytes, 16));
}

/**
 * @param  array<string, mixed>  $overrides
 * @return array<string, mixed>
 */
function filePayload(array $overrides = []): array
{
    return [
        'uuid' => (string) Str::uuid7(),
        'payload_ct' => EnvelopeFixtures::envelope(200),
        'wrapped_item_key' => EnvelopeFixtures::envelope(48),
        'payload_version' => 2,
        'chunk_count' => 3,
        ...$overrides,
    ];
}

/** A vault the given user can write to, and a lockbox inside it. */
function writableLockbox(User $user): Lockbox
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

    return Lockbox::factory()->create(['vault_id' => $vault->getKey()]);
}

describe('creating a file row', function () {
    it('stores the manifest and generates its own storage key', function () {
        $user = User::factory()->create();
        $lockbox = writableLockbox($user);
        $payload = filePayload();

        $this->actingAs($user)->post("/lockboxes/{$lockbox->uuid}/files", $payload)->assertRedirect();

        $file = VaultFile::query()->where('uuid', payloadString($payload, 'uuid'))->sole();

        expect($file->payload_ct->base64)->toBe(payloadString($payload, 'payload_ct'))
            ->and($file->chunk_count)->toBe(3)
            ->and($file->uploaded_at)->toBeNull()
            ->and($file->ciphertext_size)->toBe(0)
            ->and($file->chunks()->missing())->toBe([0, 1, 2]);

        /*
         | The object name must not be derived from anything the client sent,
         | and must not be anything the client chose. Both would put a
         | client-controlled string into a filesystem path.
         */
        expect($file->storage_key)->not->toBe($file->uuid)
            ->and(Str::isUuid($file->storage_key))->toBeTrue();
    });

    it('refuses a chunk count larger than the configured ceiling', function () {
        $user = User::factory()->create();
        $lockbox = writableLockbox($user);

        config(['vault.files.max_bytes' => 4 * 1024 * 1024, 'vault.files.chunk_bytes' => 1024 * 1024]);

        $this->actingAs($user)
            ->post("/lockboxes/{$lockbox->uuid}/files", filePayload(['chunk_count' => 5]))
            ->assertSessionHasErrors('chunk_count');
    });

    it('refuses a payload that is not a recognised envelope', function () {
        $user = User::factory()->create();
        $lockbox = writableLockbox($user);

        $this->actingAs($user)
            ->post("/lockboxes/{$lockbox->uuid}/files", filePayload(['payload_ct' => 'not-an-envelope']))
            ->assertSessionHasErrors('payload_ct');

        expect(VaultFile::query()->count())->toBe(0);
    });
});

describe('uploading chunks', function () {
    it('records each chunk and completes the file when the last one lands', function () {
        $user = User::factory()->create();
        $lockbox = writableLockbox($user);
        $file = VaultFile::factory()->create(['lockbox_id' => $lockbox->getKey(), 'chunk_count' => 3]);

        foreach ([0, 1, 2] as $index) {
            $this->actingAs($user)
                ->call('PUT', "/files/{$file->uuid}/chunks/{$index}", content: chunkBytes(100))
                ->assertOk();
        }

        $file->refresh();

        expect($file->uploaded_at)->not->toBeNull()
            ->and($file->chunks()->missing())->toBe([])
            ->and($file->ciphertext_size)->toBe(3 * 102);

        foreach ([0, 1, 2] as $index) {
            Storage::disk('local')->assertExists($file->chunkPath($index));
        }
    });

    /*
     | Out of order on purpose. Chunks are independent PUTs and a resumed upload
     | sends whatever is missing, so anything that assumed arrival order would
     | be a bug waiting for a flaky connection.
     */
    it('accepts chunks out of order', function () {
        $user = User::factory()->create();
        $lockbox = writableLockbox($user);
        $file = VaultFile::factory()->create(['lockbox_id' => $lockbox->getKey(), 'chunk_count' => 3]);

        foreach ([2, 0] as $index) {
            $this->actingAs($user)
                ->call('PUT', "/files/{$file->uuid}/chunks/{$index}", content: chunkBytes())
                ->assertOk();
        }

        expect($file->refresh()->chunks()->missing())->toBe([1])
            ->and($file->uploaded_at)->toBeNull();
    });

    /*
     | The idempotency rule, which is also what keeps the byte count honest. A
     | client that never saw the response to its last PUT retries it; if that
     | retry added to ciphertext_size, every dropped response would inflate the
     | vault's usage a little further, permanently.
     */
    it('treats a repeated chunk as a no-op rather than counting it twice', function () {
        $user = User::factory()->create();
        $lockbox = writableLockbox($user);
        $file = VaultFile::factory()->create(['lockbox_id' => $lockbox->getKey(), 'chunk_count' => 2]);

        $this->actingAs($user)
            ->call('PUT', "/files/{$file->uuid}/chunks/0", content: chunkBytes(100))
            ->assertOk()
            ->assertJson(['stored' => true]);

        $this->actingAs($user)
            ->call('PUT', "/files/{$file->uuid}/chunks/0", content: chunkBytes(500))
            ->assertOk()
            ->assertJson(['stored' => false]);

        expect($file->refresh()->ciphertext_size)->toBe(102);
    });

    it('refuses an index outside the declared chunk count', function () {
        $user = User::factory()->create();
        $lockbox = writableLockbox($user);
        $file = VaultFile::factory()->create(['lockbox_id' => $lockbox->getKey(), 'chunk_count' => 2]);

        $this->actingAs($user)
            ->call('PUT', "/files/{$file->uuid}/chunks/2", content: chunkBytes())
            ->assertSessionHasErrors('index');
    });

    it('refuses a chunk whose header names an algorithm this build does not write', function () {
        $user = User::factory()->create();
        $lockbox = writableLockbox($user);
        $file = VaultFile::factory()->create(['lockbox_id' => $lockbox->getKey(), 'chunk_count' => 2]);

        $this->actingAs($user)
            ->call('PUT', "/files/{$file->uuid}/chunks/0", content: chr(1).chr(9).random_bytes(64))
            ->assertSessionHasErrors('chunk');

        Storage::disk('local')->assertMissing($file->chunkPath(0));
    });

    it('refuses a chunk larger than the configured chunk size', function () {
        $user = User::factory()->create();
        $lockbox = writableLockbox($user);
        $file = VaultFile::factory()->create(['lockbox_id' => $lockbox->getKey(), 'chunk_count' => 2]);

        config(['vault.files.chunk_bytes' => 1024]);

        $this->actingAs($user)
            ->call('PUT', "/files/{$file->uuid}/chunks/0", content: chunkBytes(4096))
            ->assertSessionHasErrors('chunk');
    });
});

describe('quotas', function () {
    it('refuses a chunk that would take the vault past its quota', function () {
        $user = User::factory()->create();
        $lockbox = writableLockbox($user);
        $file = VaultFile::factory()->create(['lockbox_id' => $lockbox->getKey(), 'chunk_count' => 2]);

        config(['vault.files.quota_bytes' => 150]);

        $this->actingAs($user)
            ->call('PUT', "/files/{$file->uuid}/chunks/0", content: chunkBytes(100))
            ->assertOk();

        $this->actingAs($user)
            ->call('PUT', "/files/{$file->uuid}/chunks/1", content: chunkBytes(100))
            ->assertSessionHasErrors('chunk');

        expect($file->refresh()->ciphertext_size)->toBe(102)
            ->and($file->uploaded_at)->toBeNull();

        // The refused chunk must not be on the disk either: a quota that
        // stopped the accounting but not the write would not be a quota.
        Storage::disk('local')->assertMissing($file->chunkPath(1));
    });

    /*
     | Deleted files still occupy the disk until the purge sweep runs. A quota
     | that ignored them would let a vault hold unbounded data by deleting and
     | re-uploading in a loop.
     */
    it('counts trashed files against the quota', function () {
        $user = User::factory()->create();
        $lockbox = writableLockbox($user);

        VaultFile::factory()->uploaded(2, 2000)->create(['lockbox_id' => $lockbox->getKey()])->delete();

        $file = VaultFile::factory()->create(['lockbox_id' => $lockbox->getKey(), 'chunk_count' => 1]);

        config(['vault.files.quota_bytes' => 2050]);

        $this->actingAs($user)
            ->call('PUT', "/files/{$file->uuid}/chunks/0", content: chunkBytes(100))
            ->assertSessionHasErrors('chunk');
    });
});

describe('downloading', function () {
    it('serves a chunk back byte for byte, with no name attached', function () {
        $user = User::factory()->create();
        $lockbox = writableLockbox($user);
        $file = VaultFile::factory()->create(['lockbox_id' => $lockbox->getKey(), 'chunk_count' => 1]);
        $chunk = chunkBytes(200);

        $this->actingAs($user)
            ->call('PUT', "/files/{$file->uuid}/chunks/0", content: $chunk)
            ->assertOk();

        $response = $this->actingAs($user)->get("/files/{$file->uuid}/chunks/0")->assertOk();

        expect($response->getContent())->toBe($chunk)
            ->and($response->headers->get('Content-Type'))->toBe('application/octet-stream')
            ->and($response->headers->get('Cache-Control'))->toContain('no-store')
            // No filename, because the server does not have one to give.
            ->and($response->headers->get('Content-Disposition'))->toBe('attachment');
    });

    it('refuses to serve a file whose upload never finished', function () {
        $user = User::factory()->create();
        $lockbox = writableLockbox($user);
        $file = VaultFile::factory()->create(['lockbox_id' => $lockbox->getKey(), 'chunk_count' => 2]);

        $this->actingAs($user)
            ->call('PUT', "/files/{$file->uuid}/chunks/0", content: chunkBytes())
            ->assertOk();

        $this->actingAs($user)->get("/files/{$file->uuid}/chunks/0")->assertSessionHasErrors('index');
    });

    it('reports which chunks are still missing', function () {
        $user = User::factory()->create();
        $lockbox = writableLockbox($user);
        $file = VaultFile::factory()->create(['lockbox_id' => $lockbox->getKey(), 'chunk_count' => 4]);

        $this->actingAs($user)
            ->call('PUT', "/files/{$file->uuid}/chunks/1", content: chunkBytes())
            ->assertOk();

        $this->actingAs($user)
            ->getJson("/files/{$file->uuid}/status")
            ->assertOk()
            ->assertJson(['chunkCount' => 4, 'missingChunks' => [0, 2, 3], 'uploadedAt' => null]);
    });
});

describe('object storage', function () {
    /*
     | The direct answer to 2017, where the upload was written under a name built
     | from the file's own and `original_name`, `file_type` and `extension` were
     | plaintext columns. Anyone with a directory listing knew the contents of
     | the vault without decrypting a byte.
     */
    it('writes nothing to disk that names the file', function () {
        $user = User::factory()->create();
        $lockbox = writableLockbox($user);
        $file = VaultFile::factory()->create(['lockbox_id' => $lockbox->getKey(), 'chunk_count' => 1]);

        $this->actingAs($user)
            ->call('PUT', "/files/{$file->uuid}/chunks/0", content: chunkBytes())
            ->assertOk();

        $paths = Storage::disk('local')->allFiles();

        expect($paths)->toHaveCount(1);

        foreach ($paths as $path) {
            expect($path)->toBe("{$file->storage_key}/0")
                ->and(pathinfo($path, PATHINFO_EXTENSION))->toBe('');
        }
    });
});

/**
 * Runs the sweep and returns its exit code.
 *
 * `Artisan::call` rather than `$this->artisan(...)`: the latter defers the run
 * to a destructor, so a test that forgets to assert on it silently never runs
 * the command at all.
 *
 * @param  array<string, mixed>  $options
 */
function prune(array $options = []): int
{
    return Artisan::call('vault:files-prune', $options);
}

describe('pruning', function () {
    it('removes the bodies of uploads that were abandoned', function () {
        $user = User::factory()->create();
        $lockbox = writableLockbox($user);
        $file = VaultFile::factory()->create(['lockbox_id' => $lockbox->getKey(), 'chunk_count' => 2]);

        $this->actingAs($user)
            ->call('PUT', "/files/{$file->uuid}/chunks/0", content: chunkBytes())
            ->assertOk();

        $this->travel(Config::integer('vault.files.orphan_after_hours') + 1)->hours();

        expect(prune())->toBe(0);

        Storage::disk('local')->assertMissing($file->chunkPath(0));
        expect(VaultFile::withTrashed()->count())->toBe(0);
    });

    it('leaves an upload alone while it is still resumable', function () {
        $user = User::factory()->create();
        $lockbox = writableLockbox($user);
        $file = VaultFile::factory()->create(['lockbox_id' => $lockbox->getKey(), 'chunk_count' => 2]);

        $this->actingAs($user)
            ->call('PUT', "/files/{$file->uuid}/chunks/0", content: chunkBytes())
            ->assertOk();

        expect(prune())->toBe(0);

        Storage::disk('local')->assertExists($file->chunkPath(0));
        expect(VaultFile::query()->count())->toBe(1);
    });

    it('hard-deletes a trashed file once its retention window has passed', function () {
        $user = User::factory()->create();
        $lockbox = writableLockbox($user);
        $file = VaultFile::factory()->create(['lockbox_id' => $lockbox->getKey(), 'chunk_count' => 1]);

        $this->actingAs($user)
            ->call('PUT', "/files/{$file->uuid}/chunks/0", content: chunkBytes())
            ->assertOk();

        $this->actingAs($user)->delete("/files/{$file->uuid}")->assertRedirect();

        // Still restorable, and still on disk.
        expect(prune())->toBe(0);
        Storage::disk('local')->assertExists($file->chunkPath(0));

        $this->travel(Config::integer('vault.files.purge_after_days') + 1)->days();
        expect(prune())->toBe(0);

        Storage::disk('local')->assertMissing($file->chunkPath(0));
        expect(VaultFile::withTrashed()->count())->toBe(0);
    });

    it('changes nothing on a dry run', function () {
        $user = User::factory()->create();
        $lockbox = writableLockbox($user);
        $file = VaultFile::factory()->create(['lockbox_id' => $lockbox->getKey(), 'chunk_count' => 2]);

        $this->actingAs($user)
            ->call('PUT', "/files/{$file->uuid}/chunks/0", content: chunkBytes())
            ->assertOk();

        $this->travel(Config::integer('vault.files.orphan_after_hours') + 1)->hours();
        expect(prune(['--dry-run' => true]))->toBe(0);

        Storage::disk('local')->assertExists($file->chunkPath(0));
        expect(VaultFile::query()->count())->toBe(1);
    });
});
