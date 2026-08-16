<?php

/**
 * Phase 11, task 11: restore verification.
 *
 * The cases worth having are the two that a database restore alone does not
 * catch — an account whose password wrapping did not come back, and a file
 * whose body did not. Both leave a database that looks entirely healthy, and
 * the first of them is unrecoverable: there is no password reset, so a user
 * without their wrapping is locked out of their own data permanently.
 */

use App\Enums\VaultRole;
use App\Models\Lockbox;
use App\Models\User;
use App\Models\UserIdentity;
use App\Models\UserKeyWrap;
use App\Models\Vault;
use App\Models\VaultFile;
use App\Models\VaultMembership;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Storage;

/**
 * Artisan::call rather than $this->artisan(), matching the note in
 * tests/Feature/Vault/FileTest.php: the fluent helper defers its assertions to
 * a destructor, which puts the failure somewhere other than the test that
 * caused it.
 *
 * @return array{exit: int, output: string}
 */
function verifyBackup(string $arguments = ''): array
{
    $exit = Artisan::call(trim("vault:verify-backup {$arguments}"));

    return ['exit' => $exit, 'output' => Artisan::output()];
}

/**
 * A complete, healthy vault holding one two-chunk file.
 *
 * The membership matters: a vault with no live member is a fault in its own
 * right — nobody holds a key to it and nobody ever can again — so a fixture
 * without one makes every case in this file fail for a reason that has nothing
 * to do with files.
 */
function uploadedFile(): VaultFile
{
    $user = User::factory()->create();
    UserKeyWrap::factory()->for($user)->create();
    UserIdentity::factory()->for($user)->create();

    $vault = Vault::factory()->for($user, 'owner')->create();
    VaultMembership::factory()->for($vault)->for($user)->role(VaultRole::Owner)->create();

    return VaultFile::factory()->for(Lockbox::factory()->for($vault)->create())->create([
        'chunk_count' => 2,
        'uploaded_at' => now(),
    ]);
}

it('passes on a restore where every account can still unlock', function () {
    $user = User::factory()->create();
    UserKeyWrap::factory()->for($user)->create();

    $result = verifyBackup();

    expect($result['exit'])->toBe(0)
        ->and($result['output'])->toContain('No structural problems found');
});

/*
 | The one that cannot be repaired afterwards, and therefore the one this
 | command exists for. Everything looks fine: the account is there, sign-in
 | would succeed, and the vault rows are intact. What is missing is the only
 | copy of the wrapping that turns a password into a key.
 */
it('fails when an account has lost its password wrapping', function () {
    $healthy = User::factory()->create();
    UserKeyWrap::factory()->for($healthy)->create();

    User::factory()->create(['email' => 'stranded@example.com']);

    $result = verifyBackup();

    expect($result['exit'])->toBe(1)
        ->and($result['output'])
        ->toContain('no password wrapping')
        ->toContain('stranded@example.com')
        ->toContain('not usable as it stands');
});

/*
 | A recovery kit is not a substitute. It unwraps the same User Key, so an
 | account holding only a recovery wrapping is one lost kit from the same
 | permanent loss — and the point of the check is the wrapping people actually
 | use every day.
 */
it('does not accept a recovery wrapping in place of the password one', function () {
    $user = User::factory()->create(['email' => 'recovery-only@example.com']);
    UserKeyWrap::factory()->for($user)->recovery()->create();

    expect(verifyBackup()['output'])->toContain('recovery-only@example.com');
});

describe('file bodies', function () {
    it('reports a completed file whose chunks are not on the disk', function () {
        Storage::fake('local');

        $file = uploadedFile();

        $result = verifyBackup('--files');

        expect($result['exit'])->toBe(1)
            ->and($result['output'])
            ->toContain("{$file->uuid}: 2 of 2 chunks missing")
            ->toContain('cannot be reassembled');
    });

    it('passes once the chunks are where the row says they are', function () {
        Storage::fake('local');

        $file = uploadedFile();

        foreach ([0, 1] as $index) {
            Storage::disk('local')->put($file->chunkPath($index), random_bytes(64));
        }

        expect(verifyBackup('--files')['exit'])->toBe(0);
    });

    /*
     | Skipped by default rather than silently included: walking every chunk of
     | every file is an object-store request per megabyte, which is not
     | something to do by accident against a large restore.
     */
    it('says out loud that it skipped the object store', function () {
        expect(verifyBackup()['output'])->toContain('Pass --files');
    });
});
