<?php

namespace App\Console\Commands;

use App\Support\KeyAudit;
use Illuminate\Console\Command;

/**
 * The deployment-wide view: what is behind, and by how much.
 *
 * A console command rather than a page, and that is a design decision rather
 * than laziness. D11 says this is a small invited group with no organisation
 * layer, so there is no administrator role — inventing one to host a dashboard
 * would give somebody a view over everybody else's accounts that the product
 * otherwise refuses to grant. An operator has shell access by definition; a user
 * does not, and should not acquire a supervisor's view by being first to sign up.
 *
 * Each user sees the part that is theirs to act on where they can act on it: a
 * vault's rotation age on the vault, their own KDF state on their keys page.
 */
class KeyHealth extends Command
{
    protected $signature = 'vault:health';

    protected $description = 'Summarise key lifecycle health: rotations due, KDF upgrades pending, envelope versions';

    public function handle(): int
    {
        $summary = KeyAudit::summary();

        $this->newLine();
        $this->line('<options=bold>vaults</>');
        $this->line("  {$summary['vaults']} total");
        $this->line("  {$summary['vaultsNeedingRekey']} waiting on a re-key demanded by a revocation");
        $this->line("  {$summary['vaultsDueForRotation']} past the reminder interval they set");

        if ($summary['vaultsNeedingRekey'] > 0) {
            /*
             | Called out separately from the count above, because the two are
             | not the same kind of overdue. A reminder interval elapsing is a
             | preference; an unfulfilled re-key means a removed member's cached
             | key still opens everything written since they left.
             */
            $this->newLine();
            $this->warn(
                '  A required re-key is not a reminder. Until it happens, whoever was removed can '
                .'still read everything written since — rotation is the second half of revocation.'
            );
        }

        $this->newLine();
        $this->line('<options=bold>accounts</>');
        $this->line("  {$summary['usersBehindOnKdf']} on password stretching below this deployment's settings");
        $this->line("  {$summary['usersWithoutIdentity']} with no published keys, who cannot be shared with");

        if ($summary['usersBehindOnKdf'] > 0) {
            // Nothing to do about it, and saying so is the point: an operator
            // looking at a non-zero number needs to know it resolves itself.
            $this->newLine();
            $this->comment(
                '  These upgrade silently on next login. Nothing on the server can do it — '
                .'re-wrapping needs the password, which exists only in a browser.'
            );
        }

        $this->newLine();
        $this->line('<options=bold>envelopes</>');
        $this->line("  {$summary['totalEnvelopes']} payloads stored");
        $this->line("  {$summary['legacyEnvelopes']} on the old version, movable by a re-seal");
        $this->line("  {$summary['immutableEnvelopes']} on the old version and immutable (archived versions)");

        if ($summary['legacyEnvelopes'] > 0) {
            /*
             | Names the operation, because "lazily on write" is not a migration
             | in a password manager: the payloads nobody edits are the majority
             | and the long-lived ones.
             */
            $this->newLine();
            $this->comment(
                '  A vault owner moves these from the vault’s re-seal page. Waiting for edits will '
                .'not clear them — a payload nobody touches stays on the old envelope indefinitely.'
            );
        }

        if ($summary['immutableEnvelopes'] > 0) {
            /*
             | Separated from the number above so it is not read as outstanding
             | work. Nothing can move these and nothing should: an archive that
             | could be rewritten is a rollback channel for a credential somebody
             | rotated *because* it leaked.
             */
            $this->newLine();
            $this->comment(
                '  The immutable ones are a secret’s history, which is never rewritten by design. '
                .'They leave when the retention policy removes them, and not before.'
            );
        }

        $this->newLine();

        return self::SUCCESS;
    }
}
