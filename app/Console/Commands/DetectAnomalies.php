<?php

namespace App\Console\Commands;

use App\Enums\AuditAction;
use App\Models\AuditEvent;
use Illuminate\Console\Command;
use Illuminate\Mail\Message;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Mail;

/**
 * Reads the audit log for the shapes worth waking somebody up about (Phase 12,
 * task 4).
 *
 * **Be honest about what this is.** It is four thresholds over a table, not
 * detection. The server cannot tell a person doing a week's work in an afternoon
 * from somebody emptying a vault they have just taken, because the difference
 * between those two is entirely in what the actor intended and the server cannot
 * read a single thing either of them touched. What it can say is *this is
 * unusual for this deployment*, which is a smaller claim and the only true one.
 *
 * So the wording that goes out says that, and the thresholds are configurable
 * rather than clever. A detector that cried wolf would be muted inside a month,
 * and the alert that mattered would be muted with it — the same argument that
 * keeps `AccountSecurityAlert` down to two actions.
 *
 * **Two of the four fire on a single event**, because for those the count is not
 * the question: using a recovery kit is the one flow that grants a session
 * without the password, and an export is the widest read the application allows.
 * Neither is wrong, both are rare, and both are worth an operator seeing on the
 * day rather than the week.
 *
 * This alerts the *operator*. The account holder is told separately and
 * immediately by `AccountSecurityAlert`, over a channel a takeover does not
 * control. Neither replaces the other: one asks "was this you?", this one asks
 * "is something happening to this deployment?".
 *
 * Run daily from the scheduler.
 */
class DetectAnomalies extends Command
{
    protected $signature = 'vault:anomalies
        {--hours=24 : How far back to look}
        {--print : Write the report to the console instead of sending it}';

    protected $description = 'Report unusual patterns in the audit log to the operator';

    public function handle(): int
    {
        $hours = max(1, (int) $this->option('hours'));
        $since = now()->subHours($hours);

        $findings = array_values(array_filter([
            $this->massReveals($since),
            $this->failedSignIns($since),
            $this->singleEvent($since, AuditAction::RecoveryUsed, 'A recovery kit was used to sign in'),
            $this->singleEvent($since, AuditAction::AccountExported, 'An account was exported in full'),
        ]));

        $report = $this->compose($findings, $since, $hours);

        if ($this->option('print')) {
            $this->line($report);

            return self::SUCCESS;
        }

        $operator = Config::string('vault.alerts.address', '');

        if ($operator === '') {
            /*
             | Failing rather than quietly doing nothing, for the same reason
             | `vault:audit-anchor` does. A monitoring job that exits zero
             | having had nowhere to send its findings leaves the operator
             | believing they are being watched over, which is worse than
             | knowing they are not.
             */
            $this->error(
                'No alert address is configured (VAULT_ALERT_ADDRESS). Nothing here can be reported, '
                .'so the audit log is being written and nobody is reading it.'
            );

            return self::FAILURE;
        }

        if ($findings === []) {
            // Silence is the correct output for a quiet day. A daily "nothing
            // to report" is how somebody learns to stop opening these.
            $this->info("Nothing unusual in the last {$hours} hours.");

            return self::SUCCESS;
        }

        Mail::raw($report, function (Message $message) use ($operator, $findings): void {
            $message->to($operator)->subject(
                count($findings) === 1
                    ? 'Vault: something unusual in the audit log'
                    : 'Vault: '.count($findings).' unusual things in the audit log'
            );
        });

        $this->warn(count($findings).' finding(s) reported to '.$operator.'.');

        return self::SUCCESS;
    }

    /**
     * One person revealing a great many secrets.
     *
     * `secret.revealed` is browser-reported and signed, which matters here: it
     * is one of the two events the server cannot witness for itself, so a
     * compromised server cannot fabricate this pattern and — more usefully —
     * cannot suppress it without the missing signatures being visible.
     */
    private function massReveals(Carbon $since): ?string
    {
        $threshold = Config::integer('vault.alerts.reveals_per_day', 50);

        $rows = AuditEvent::query()
            ->where('action', AuditAction::SecretRevealed)
            ->where('created_at', '>=', $since)
            ->whereNotNull('actor_uuid')
            ->selectRaw('actor_uuid, count(*) as total')
            ->groupBy('actor_uuid')
            /*
             | `havingRaw('count(*) …')` rather than `having('total', …)`.
             | Postgres does not allow a select alias in HAVING, so the alias
             | form runs on SQLite and throws "column total does not exist" on
             | the database this actually deploys to. Caught by the Postgres CI
             | job rather than by a production run, which is the whole argument
             | for that job existing.
             */
            ->havingRaw('count(*) >= ?', [$threshold])
            ->get();

        if ($rows->isEmpty()) {
            return null;
        }

        $lines = [];

        foreach ($rows as $row) {
            $total = $row->getAttribute('total');
            $actor = $row->getAttribute('actor_uuid');

            $lines[] = sprintf(
                '    %s revealed %d secrets',
                is_string($actor) ? $actor : 'an unnamed actor',
                is_numeric($total) ? (int) $total : 0,
            );
        }

        return "Unusually many secrets revealed (threshold {$threshold}):\n".implode("\n", $lines);
    }

    /**
     * Sign-in attempts that failed.
     *
     * Counted in total rather than per account, because `auth.login_failed` has
     * no actor by design — the whole point of that event is that the address may
     * belong to nobody, and recording which account was guessed at would make
     * the log itself an account-existence oracle (SR6).
     */
    private function failedSignIns(Carbon $since): ?string
    {
        $threshold = Config::integer('vault.alerts.failed_sign_ins_per_day', 20);

        $total = AuditEvent::query()
            ->where('action', AuditAction::LoginFailed)
            ->where('created_at', '>=', $since)
            ->count();

        if ($total < $threshold) {
            return null;
        }

        $sources = AuditEvent::query()
            ->where('action', AuditAction::LoginFailed)
            ->where('created_at', '>=', $since)
            ->distinct()
            ->count('ip_hash');

        return "{$total} failed sign-in attempts from {$sources} distinct source(s), threshold "
            ."{$threshold}. The log holds a keyed hash of each address rather than the address, so "
            .'these can be told apart but not looked up.';
    }

    /** An action rare enough that one occurrence is the finding. */
    private function singleEvent(Carbon $since, AuditAction $action, string $headline): ?string
    {
        $events = AuditEvent::query()
            ->where('action', $action)
            ->where('created_at', '>=', $since)
            ->orderBy('seq')
            ->get(['actor_uuid', 'created_at', 'metadata']);

        if ($events->isEmpty()) {
            return null;
        }

        $lines = $events->map(fn (AuditEvent $event): string => sprintf(
            '    %s  %s  %s',
            $event->created_at?->toIso8601String() ?? 'unknown time',
            $event->actor_uuid ?? 'no actor',
            $event->metadata,
        ))->implode("\n");

        return "{$headline} ({$events->count()}):\n{$lines}";
    }

    /** @param  list<string>  $findings */
    private function compose(array $findings, Carbon $since, int $hours): string
    {
        if ($findings === []) {
            return "Vault: nothing unusual in the {$hours} hours since {$since->toIso8601String()}.\n";
        }

        return sprintf(
            "Vault: unusual activity in the last %d hours (since %s).\n\n%s\n\n%s\n",
            $hours,
            $since->toIso8601String(),
            implode("\n\n", $findings),
            "These are thresholds, not conclusions. The server cannot read anything it stores, so it\n"
                ."cannot tell a busy afternoon from somebody emptying a vault — only that this is\n"
                ."unusual for this deployment. The full log is at /account/activity for an account and\n"
                .'in `audit_events` for everything.',
        );
    }
}
