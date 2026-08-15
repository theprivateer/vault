<?php

namespace App\Console\Commands;

use App\Support\AuditLog;
use Illuminate\Console\Command;
use Illuminate\Mail\Message;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Mail;

/**
 * Publishes the chain head somewhere the server does not control.
 *
 * **This is the only part of the audit design that a compromised server cannot
 * defeat.** The chain by itself stops careless tampering: change one row and
 * every hash after it stops matching. It does nothing against a server that
 * rewrites the log from a chosen point and recomputes the rest, because it holds
 * every input to that computation.
 *
 * What it does not hold is yesterday's email. Once `seq 4,812 = a3f1…` has left
 * the building, any rewritten history that disagrees with it is provably a
 * rewrite — the operator has a copy of what the chain said before, and the two
 * cannot both be true. That is the whole mechanism, and it is worth being clear
 * that its strength comes entirely from the anchor being *outside*: mailing it
 * to an address the same server also administers would prove nothing.
 *
 * Run daily from the scheduler.
 */
class AnchorAuditChain extends Command
{
    protected $signature = 'vault:audit-anchor {--print : Write the anchor to the console instead of sending it}';

    protected $description = 'Publish the audit chain head to the operator, as an external record';

    public function handle(): int
    {
        $head = AuditLog::head();

        $anchor = sprintf(
            "Vault audit anchor\n\nAs at %s the audit log stands at:\n\n  seq  %d\n  head %s\n\n"
                ."Keep this message. If `php artisan vault:audit-verify` ever reports a head that\n"
                ."disagrees with an anchor you still hold, the log was rewritten — the chain cannot\n"
                ."tell you that on its own, because whoever rewrote it could recompute every hash.\n",
            now()->toIso8601String(),
            $head->seq,
            $head->hash,
        );

        if ($this->option('print')) {
            $this->line($anchor);

            return self::SUCCESS;
        }

        $operator = Config::string('vault.audit.anchor_address', '');

        if ($operator === '') {
            /*
             | Failing rather than quietly doing nothing. An anchoring job that
             | logs "no address configured" and exits zero is worse than no job
             | at all: the operator believes there is an external record, and
             | there is not.
             */
            $this->error(
                'No anchor address is configured (VAULT_AUDIT_ANCHOR_ADDRESS). The chain head has '
                .'nowhere external to go, which means the audit log currently has no defence '
                .'against being rewritten wholesale.'
            );

            return self::FAILURE;
        }

        Mail::raw($anchor, function (Message $message) use ($operator, $head): void {
            $message->to($operator)->subject("Vault audit anchor — seq {$head->seq}");
        });

        $this->info("Anchored seq {$head->seq} to {$operator}.");

        return self::SUCCESS;
    }
}
