<?php

namespace App\Console\Commands;

use App\Models\Vault;
use App\Support\KeyAudit;
use Illuminate\Console\Command;

/**
 * Reports every structural fault in the key hierarchy, vault by vault.
 *
 * **What this cannot check, said first because it is most of the answer.** This
 * server holds no key. It cannot tell whether a wrapped Item Key opens under the
 * Vault Key it claims to be wrapped by, whether a payload decrypts, or whether a
 * member's sealed key is the one they believe it is. Those are answered in a
 * browser or not at all — a command that implied otherwise would report health
 * it never measured, which is worse than reporting nothing.
 *
 * What it does check is structural and each fault has a real consequence: a
 * member stranded on an old epoch holds access that silently does not work; a
 * vault told to re-key and never re-keyed leaves a removed member's cached key
 * opening everything written since; a vault with no live administrator can never
 * be shared, rotated or deleted by anybody.
 *
 * Exits non-zero when anything is wrong, so it can sit in a scheduler and be
 * noticed.
 */
class VerifyKeys extends Command
{
    protected $signature = 'vault:verify-keys {--vault= : Check only this vault UUID}';

    protected $description = 'Report structural faults in vault key state: epochs, membership, envelopes';

    public function handle(): int
    {
        $query = Vault::withTrashed()->orderBy('id');

        if (is_string($uuid = $this->option('vault'))) {
            $query->where('uuid', $uuid);
        }

        $checked = 0;
        $faulty = 0;
        $faults = 0;

        foreach ($query->lazy() as $vault) {
            $checked++;
            $found = KeyAudit::faultsIn($vault);

            if ($found === []) {
                continue;
            }

            $faulty++;
            $faults += count($found);

            $this->newLine();
            $this->warn("vault {$vault->uuid}".($vault->trashed() ? ' (deleted, in grace period)' : ''));

            foreach ($found as $fault) {
                $this->line('  - '.$fault);
            }
        }

        $this->newLine();

        if ($checked === 0) {
            $this->info('No vaults to check.');

            return self::SUCCESS;
        }

        if ($faults === 0) {
            $this->info("{$checked} ".($checked === 1 ? 'vault' : 'vaults').' checked, no faults found.');
        } else {
            $this->error("{$faults} fault".($faults === 1 ? '' : 's')." across {$faulty} of {$checked} vaults.");
        }

        /*
         | Stated on every run, including a clean one. "No faults found" invites
         | the reading "everything is fine", and the most important limit of this
         | command is exactly the thing a green result would let somebody forget.
         */
        $this->newLine();
        $this->comment(
            'This checks structure only. Whether a key actually opens what it claims to is not '
            .'knowable here — the server holds none of them — and is answered in a browser.'
        );

        return $faults === 0 ? self::SUCCESS : self::FAILURE;
    }
}
