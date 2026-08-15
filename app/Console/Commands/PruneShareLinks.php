<?php

namespace App\Console\Commands;

use App\Enums\AuditAction;
use App\Models\ShareLink;
use App\Support\AuditLog;
use Illuminate\Console\Command;

/**
 * Removes share links that can no longer be opened.
 *
 * Expired, revoked and exhausted rows all go. Keeping a spent link would mean
 * storing somebody's credential — sealed, but stored — for no purpose whatever:
 * it can never be handed out again, and the audit log already records that it
 * existed, that it was created, and when it was opened.
 *
 * That is the difference between this sweep and the file one. A purged file is
 * removed after a grace period *because it might be restored*; a spent share
 * link has no such state. Nothing here is recoverable and nothing should be.
 */
class PruneShareLinks extends Command
{
    protected $signature = 'vault:links-prune {--dry-run : List what would be removed and change nothing}';

    protected $description = 'Delete one-time share links that have expired, been revoked or been used up';

    public function handle(): int
    {
        $dryRun = (bool) $this->option('dry-run');
        $finished = ShareLink::query()->finished()->get();

        foreach ($finished as $link) {
            $this->line("  {$link->uuid} ({$link->view_count} of {$link->max_views} views used)");

            if ($dryRun) {
                continue;
            }

            /*
             | Recorded before the row goes, with no actor: nothing here was
             | done by a person. The count is the fact worth keeping — a link
             | that expired unopened and one that was opened and then expired
             | are very different things to read about afterwards.
             */
            AuditLog::record(AuditAction::ShareLinkExpired, $link, [
                'count' => $link->view_count,
                'max_views' => $link->max_views,
            ], actor: null);

            $link->delete();
        }

        $this->info(sprintf(
            '%s %d finished share link(s).',
            $dryRun ? 'Would remove' : 'Removed',
            $finished->count(),
        ));

        return self::SUCCESS;
    }
}
