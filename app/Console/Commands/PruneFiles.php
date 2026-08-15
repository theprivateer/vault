<?php

namespace App\Console\Commands;

use App\Models\VaultFile;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Config;

/**
 * Removes file bodies the database no longer has a live row for.
 *
 * Two kinds of rubbish accumulate, and they are not the same problem:
 *
 *  - **Orphans.** An upload that never finished — a closed tab, a lost
 *    connection — leaves a row with `uploaded_at` still null and however many
 *    chunks did land sitting on the disk. Those are given a grace period long
 *    enough to survive a laptop lid, because a resumed upload is the feature
 *    that grace period exists for, and are then removed row and all.
 *
 *  - **Purges.** A deleted file is soft-deleted, so it can be restored, and its
 *    bytes stay where they are. After the retention window they are unlinked
 *    and the row is force-deleted.
 *
 * Bytes go first, in both cases. If the process dies between the two steps, what
 * is left is a row pointing at nothing — which the next run will try again and
 * which is visible — rather than an object nothing points at, which nothing
 * would ever look for again.
 */
class PruneFiles extends Command
{
    protected $signature = 'vault:files-prune {--dry-run : List what would be removed and change nothing}';

    protected $description = 'Delete the bodies of abandoned uploads and purged file attachments';

    public function handle(): int
    {
        $dryRun = (bool) $this->option('dry-run');

        $orphans = VaultFile::query()
            ->whereNull('uploaded_at')
            ->where('created_at', '<', now()->subHours(Config::integer('vault.files.orphan_after_hours')))
            ->get();

        $purged = VaultFile::query()
            ->onlyTrashed()
            ->where('deleted_at', '<', now()->subDays(Config::integer('vault.files.purge_after_days')))
            ->get();

        foreach ($orphans as $file) {
            $this->remove($file, 'abandoned upload', $dryRun);
        }

        foreach ($purged as $file) {
            $this->remove($file, 'purged', $dryRun);
        }

        $this->info(sprintf(
            '%s %d abandoned upload(s) and %d purged file(s).',
            $dryRun ? 'Would remove' : 'Removed',
            $orphans->count(),
            $purged->count(),
        ));

        return self::SUCCESS;
    }

    /**
     * Deletes the whole storage directory rather than each chunk in turn.
     *
     * The directory holds nothing but this file's chunks — it is named by the
     * row's random `storage_key` and nothing else is ever written into it — so
     * removing it cannot take anything else with it, and it removes chunks the
     * row's bitmap does not know about as well as the ones it does.
     */
    private function remove(VaultFile $file, string $reason, bool $dryRun): void
    {
        $this->line("  {$file->uuid} ({$reason}, {$file->ciphertext_size} bytes)");

        if ($dryRun) {
            return;
        }

        $file->disk()->deleteDirectory($file->storageDirectory());
        $file->forceDelete();
    }
}
