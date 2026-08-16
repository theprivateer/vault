<?php

namespace App\Console\Commands;

use App\Models\User;
use App\Models\UserKeyWrap;
use App\Models\VaultFile;
use App\Support\KeyAudit;
use Illuminate\Console\Command;

/**
 * Answers one question about a restored copy: could somebody still get in, and
 * is everything they would reach for still here?
 *
 * A backup you have not restored is a hypothesis. This is what you run against
 * the restore — point the connection at the scratch database and run it there,
 * not against production, where it will happily tell you that production is
 * fine.
 *
 * Two things make a restore of *this* application fail in ways an ordinary web
 * application's would not:
 *
 *  - **A user with no password wrapping cannot be helped by anybody.** There is
 *    no reset. If a dump caught `users` and missed `user_key_wraps`, the
 *    accounts exist, sign-in succeeds, and every one of them is locked out of
 *    their own data permanently. That is the single worst outcome available
 *    here and it is invisible until somebody tries.
 *  - **File bodies are not in the database.** They live on an object store,
 *    which is a second thing to back up and the one people forget. Rows for a
 *    file whose chunks are gone look completely healthy.
 *
 * What it cannot check is the same thing nothing on this server can check: that
 * a payload actually decrypts. That needs a key, and there is none here. The
 * closing line says so, because a verifier that implies more than it measured
 * is worse than no verifier.
 */
class VerifyBackup extends Command
{
    protected $signature = 'vault:verify-backup {--files : Also confirm every stored file chunk is present}';

    protected $description = 'Verify a restored copy is complete and usable: wrappings, key state, audit chain, file bodies';

    public function handle(): int
    {
        $faults = 0;

        $faults += $this->checkAccountsCanUnlock();
        $faults += $this->checkKeyState();
        $faults += $this->checkAuditChain();

        if ($this->option('files')) {
            $faults += $this->checkFileBodies();
        } else {
            $this->newLine();
            $this->comment('  File bodies were not checked. Pass --files to walk the object store.');
        }

        $this->newLine();

        if ($faults > 0) {
            $this->error("{$faults} problem".($faults === 1 ? '' : 's').' found. This restore is not usable as it stands.');

            return self::FAILURE;
        }

        $this->info('No structural problems found in this restore.');

        /*
         | Said on a clean run, deliberately. Everything above is structural:
         | rows present, references intact, hashes consistent. Whether the
         | ciphertext still opens is a question only a browser holding a key can
         | answer, and the only honest way to finish a restore rehearsal is to
         | sign in to it and unlock a real vault.
         */
        $this->newLine();
        $this->comment(
            '  Structure only. Nothing here decrypted anything, because nothing here can. '
            .'Finish the rehearsal by signing in to this restore and unlocking a vault.'
        );

        return self::SUCCESS;
    }

    /**
     * The failure that cannot be repaired afterwards.
     */
    private function checkAccountsCanUnlock(): int
    {
        $total = User::query()->count();

        $stranded = User::query()
            ->whereDoesntHave('keyWraps', fn ($query) => $query->where('method', UserKeyWrap::METHOD_PASSWORD))
            ->get()
            ->map(fn (User $user): string => $user->email);

        $this->newLine();
        $this->line('<options=bold>accounts</>');
        $this->line("  {$total} in this restore");

        if ($stranded->isEmpty()) {
            $this->line('  every one of them has the password wrapping it needs to unlock');

            return 0;
        }

        $this->error("  {$stranded->count()} with no password wrapping — permanently locked out of their own data:");

        foreach ($stranded as $email) {
            $this->line("    - {$email}");
        }

        return $stranded->count();
    }

    private function checkKeyState(): int
    {
        $summary = KeyAudit::summary();

        $this->newLine();
        $this->line('<options=bold>vaults</>');
        $this->line("  {$summary['vaults']} vaults, {$summary['totalEnvelopes']} stored payloads");

        /*
         | Re-uses the structural sweep rather than repeating it, so the two
         | commands cannot drift into disagreeing about what a fault is.
         |
         | `$this->call` and not `Artisan::call`: the latter runs the child
         | against its own buffer, which then becomes the buffer `Artisan::output()`
         | returns to whoever called *this* command — so a caller collecting the
         | output of a restore check would receive the tail of a sub-command and
         | nothing else.
         */
        return $this->call('vault:verify-keys') === self::SUCCESS ? 0 : 1;
    }

    private function checkAuditChain(): int
    {
        $this->newLine();
        $this->line('<options=bold>audit log</>');

        $exit = $this->call('vault:audit-verify');

        /*
         | A broken chain in a restore usually means the dump caught the table
         | mid-write rather than that anybody tampered with anything — and it
         | still has to be looked at, because "probably just the dump" is what
         | tampering would like to be mistaken for.
         */
        return $exit === self::SUCCESS ? 0 : 1;
    }

    /**
     * The half of the data that is not in the database.
     */
    private function checkFileBodies(): int
    {
        $files = 0;
        $missing = 0;
        $chunks = 0;

        $this->newLine();
        $this->line('<options=bold>file bodies</>');

        foreach (VaultFile::withTrashed()->whereNotNull('uploaded_at')->lazy() as $file) {
            $files++;
            $absent = [];

            foreach (range(0, $file->chunk_count - 1) as $index) {
                $chunks++;

                if (! $file->disk()->exists($file->chunkPath($index))) {
                    $absent[] = $index;
                }
            }

            if ($absent === []) {
                continue;
            }

            $missing++;
            $this->error("  {$file->uuid}: ".count($absent)." of {$file->chunk_count} chunks missing");
        }

        $this->line("  {$files} completed files, {$chunks} chunks expected");

        if ($missing === 0) {
            $this->line('  every chunk is where its row says it is');

            return 0;
        }

        $this->error("  {$missing} file".($missing === 1 ? '' : 's').' cannot be reassembled from this restore.');

        return $missing;
    }
}
