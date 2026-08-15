<?php

namespace App\Console\Commands;

use App\Enums\AuditAction;
use App\Models\Lockbox;
use App\Models\Secret;
use App\Models\Vault;
use App\Support\AuditLog;
use App\Support\HistoryRetention;
use Illuminate\Console\Command;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Support\Facades\DB;

/**
 * Ages out superseded payloads.
 *
 * The other half of the retention policy. The count limit is applied the moment
 * an edit archives something, because that is when the count changes; nothing
 * about a secret nobody has touched in a year changes until the clock does, so
 * the age limit needs something that runs on a timer.
 *
 * The count limit is applied here too, as a sweep rather than a write. It is
 * not redundant: shortening a vault's policy prunes what is already stored, but
 * a secret whose lockbox was restored from the bin, or a row written by an
 * older build, can sit above the limit with nothing to trigger a trim. A
 * nightly pass over the whole table is cheap and means the number a vault
 * displays is the number that is true.
 *
 * **Why this logs and the write path does not.** A prune during an edit is a
 * deterministic consequence of an action already in the log; recording it again
 * would put a second line beside every edit of an active secret and bury the
 * events somebody is actually looking for. A prune here was caused by nothing
 * but time passing, and if it is not recorded, nothing records it.
 */
class PruneHistory extends Command
{
    protected $signature = 'vault:history-prune {--dry-run : List what would be removed and change nothing}';

    protected $description = 'Remove superseded secret payloads that have passed their vault’s retention policy';

    public function handle(): int
    {
        $dryRun = (bool) $this->option('dry-run');
        $expired = 0;
        $retained = 0;

        foreach (Vault::withTrashed()->get() as $vault) {
            $expired += $this->sweep($vault, 'expired', $dryRun);
            $retained += $this->sweep($vault, 'retained', $dryRun);
        }

        $this->info(sprintf(
            '%s %d expired version(s) and %d beyond the retained count.',
            $dryRun ? 'Would remove' : 'Removed',
            $expired,
            $retained,
        ));

        return self::SUCCESS;
    }

    /**
     * One vault, one reason.
     *
     * Trashed vaults are swept as well as live ones. A vault in its deletion
     * grace period is still storing every old password it ever held, and the
     * retention policy is about what the *server* keeps — pausing it because
     * somebody clicked delete would keep the data longer, which is precisely
     * backwards.
     */
    private function sweep(Vault $vault, string $reason, bool $dryRun): int
    {
        $removed = 0;

        foreach ($this->secretsIn($vault) as $secret) {
            $count = $reason === 'expired'
                ? $this->expire($vault, $secret, $dryRun)
                : $this->trim($vault, $secret, $dryRun);

            if ($count === 0) {
                continue;
            }

            $this->line("  {$secret->uuid}: {$count} version(s) {$reason}");
            $removed += $count;

            if (! $dryRun) {
                /*
                 | No actor. A sweep has no human behind it, and attributing it
                 | to whoever last edited the secret would put a name against a
                 | deletion they did not perform.
                 */
                AuditLog::record(AuditAction::SecretHistoryPruned, $secret, [
                    'count' => $count,
                    'reason' => $reason,
                ], actor: null);
            }
        }

        return $removed;
    }

    private function expire(Vault $vault, Secret $secret, bool $dryRun): int
    {
        $cutoff = now()->subDays($vault->historyMaxAgeDays());

        $query = DB::table('secret_versions')
            ->where('secret_id', $secret->getKey())
            ->where('created_at', '<', $cutoff);

        return $dryRun ? $query->count() : $query->delete();
    }

    private function trim(Vault $vault, Secret $secret, bool $dryRun): int
    {
        if ($dryRun) {
            return max(0, $secret->versions()->count() - $vault->historyMaxVersions());
        }

        return DB::transaction(fn (): int => HistoryRetention::trimToCount($secret, $vault));
    }

    /**
     * The vault's secrets that actually have history, trashed ones included.
     *
     * `whereHas` rather than a scan of every secret: most rows in a mature
     * vault have never been edited, and a nightly job that woke up to do
     * nothing for each of them would grow with the vault rather than with the
     * thing it is cleaning up.
     *
     * @return Collection<int, Secret>
     */
    private function secretsIn(Vault $vault): Collection
    {
        $lockboxes = Lockbox::withTrashed()
            ->where('vault_id', $vault->getKey())
            ->pluck('id');

        return Secret::withTrashed()
            ->whereIn('lockbox_id', $lockboxes)
            ->whereHas('versions')
            ->get(['id', 'uuid']);
    }
}
