<?php

namespace App\Console\Commands;

use App\Http\Controllers\CryptoWorkerController;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Throwable;

/**
 * Is this deployment configured the way the design assumes (Phase 12, task 1)?
 *
 * Every check here corresponds to a decision made somewhere in `docs/`, and each
 * one is a setting that can be wrong without anything failing. That is the whole
 * category: an application with `APP_DEBUG=true`, no external audit anchor, a
 * local file disk and a mail driver pointed at a log file works perfectly. It
 * serves pages, it stores ciphertext, nobody notices. It has simply stopped
 * being the thing the threat model describes.
 *
 * Run it after every deploy. It reads configuration and one database privilege;
 * it changes nothing.
 *
 * **Failures block, warnings do not.** A failure means a stated property of the
 * design is not true on this box. A warning means something is probably wrong
 * but has a legitimate reading — a single-user deployment with no attachments
 * genuinely does not need an object store.
 */
class Preflight extends Command
{
    protected $signature = 'vault:preflight';

    protected $description = 'Check a deployment against the assumptions the design makes';

    private int $failures = 0;

    private int $warnings = 0;

    public function handle(): int
    {
        $this->newLine();
        $this->line('<options=bold>the application</>');

        $this->must(
            ! Config::boolean('app.debug'),
            'APP_DEBUG is off',
            'APP_DEBUG is on, which renders stack traces and configuration to anybody who triggers an error.'
        );

        $this->must(
            Str::startsWith(Config::string('app.url'), 'https://'),
            'APP_URL is https',
            'APP_URL is not https. Absolute links, and the cookies that follow them, are built from it.'
        );

        $this->must(
            Config::string('app.key') !== '',
            'APP_KEY is set',
            'APP_KEY is empty. It encrypts the session and keys the HMAC over addresses in the audit log.'
        );

        $this->newLine();
        $this->line('<options=bold>the audit log</>');

        $this->must(
            Config::string('vault.audit.anchor_address') !== '',
            'the chain head is anchored off this server',
            'VAULT_AUDIT_ANCHOR_ADDRESS is unset, so the audit log has no defence against being '
                .'rewritten wholesale — the chain alone cannot detect that, because whoever rewrote '
                .'it holds every input to the hash.'
        );

        $this->should(
            ! $this->anchorSharesDomainWithApp(),
            'the anchor address is not on this application’s own domain',
            'The anchor address is on the same domain as APP_URL. It may still be an independent '
                .'mailbox; if this server can administer it, the anchor proves nothing.'
        );

        $this->must(
            ! in_array(Config::string('mail.default'), ['log', 'array'], true),
            'mail has somewhere real to go',
            'MAIL_MAILER is "'.Config::string('mail.default').'", so the audit anchor, the anomaly '
                .'report and every account security alert are being written to a file on this server.'
        );

        $this->should(
            Config::string('vault.alerts.address') !== '',
            'anomalies are reported to somebody',
            'VAULT_ALERT_ADDRESS is unset, so vault:anomalies fails every night rather than reporting.'
        );

        $this->checkAuditGrants();

        $this->newLine();
        $this->line('<options=bold>storage</>');

        $this->must(
            Config::string('database.default') !== 'sqlite',
            'the database is not SQLite',
            'The default connection is SQLite. Production is Postgres — see docs/04, where three '
                .'column-type decisions depend on a database that enforces them.'
        );

        $this->should(
            Config::string('vault.files.disk') !== 'local',
            'file bodies are on an object store',
            'VAULT_FILES_DISK is "local", so attachment ciphertext sits on the application disk — a '
                .'second thing to back up, and the one people forget until a restore is missing it.'
        );

        $this->must(
            is_file(storage_path(CryptoWorkerController::PATH)),
            'the crypto worker has been built',
            'The crypto worker is missing from '.CryptoWorkerController::PATH.', so every page will '
                .'report that encryption is unavailable. Run `npm run build` on the deployment; the '
                .'worker is built separately from the main bundle and a deploy script that only runs '
                .'`vite build` will skip it.'
        );

        $this->newLine();
        $this->line('<options=bold>what a log could hold</>');

        $this->should(
            $this->argumentsAreHiddenFromTraces(),
            'stack traces carry no function arguments',
            'zend.exception_ignore_args is off, so exceptions collect the arguments of every frame — '
                .'request payloads, ciphertext, the values passed to a hash. The log file itself is '
                .'safe either way, because getTraceAsString() truncates strings to 15 characters; '
                .'what is not safe is an error tracker, which serialises getTrace() with the values '
                .'intact. Turn it on in php.ini before adding one, and treat this as a failure rather '
                .'than a warning from the day you do.'
        );

        $this->should(
            ! in_array('single', Config::array('logging.channels.stack.channels', []), true),
            'the log rotates and expires',
            'LOG_STACK includes "single", so one file accumulates for the life of the server. The '
                .'leak canary sweeps the logs, which is a claim they hold nothing worth stealing.'
        );

        $this->must(
            Config::boolean('session.encrypt'),
            'the session store is encrypted',
            'SESSION_ENCRYPT is off.'
        );

        $this->newLine();

        if ($this->failures > 0) {
            $this->error(
                "{$this->failures} check".($this->failures === 1 ? '' : 's').' failed. This deployment '
                .'is not the one the threat model describes.'
            );

            return self::FAILURE;
        }

        $this->info(
            $this->warnings > 0
                ? "No failures, {$this->warnings} warning".($this->warnings === 1 ? '' : 's').' worth reading.'
                : 'Everything this can check is as the design assumes.'
        );

        /*
         | Said on a clean run, deliberately, and it is the same closing note as
         | `vault:verify-backup`. Configuration is what this reads. Whether the
         | scheduler actually runs, whether the backups actually restore and
         | whether anybody reads the anchor are facts about the world.
         */
        $this->newLine();
        $this->comment(
            '  Configuration only. That the scheduler runs, that backups restore, and that somebody '
            .'reads the anchor are not things this can see from in here.'
        );

        return self::SUCCESS;
    }

    /**
     * The `REVOKE` that makes the audit log append-only below the application.
     *
     * The only check here that asks the database a question rather than reading
     * a config file, and the only one that can confirm a deployment step was
     * actually performed. Skipped on anything but Postgres, where the grant
     * model does not exist.
     */
    private function checkAuditGrants(): void
    {
        if (DB::connection()->getDriverName() !== 'pgsql') {
            return;
        }

        try {
            $row = DB::selectOne(
                "select has_table_privilege(current_user, 'audit_events', 'UPDATE') as may_update, "
                ."has_table_privilege(current_user, 'audit_events', 'DELETE') as may_delete, "
                ."has_table_privilege(current_user, 'audit_events', 'INSERT') as may_insert"
            );
        } catch (Throwable) {
            $this->warnings++;
            $this->line('  <fg=yellow>?</> could not read the grants on audit_events');

            return;
        }

        $grants = (array) $row;
        $username = DB::connection()->getConfig('username');

        $this->must(
            ! ($grants['may_update'] ?? true) && ! ($grants['may_delete'] ?? true),
            'the database refuses UPDATE and DELETE on audit_events',
            'This connection may UPDATE or DELETE audit_events. The model and the routes both refuse '
                .'to, and both are code a future change can undo. Run: REVOKE UPDATE, DELETE ON '
                .'audit_events FROM '.(is_string($username) ? $username : '<the application role>').';'
        );

        $this->must(
            (bool) ($grants['may_insert'] ?? false),
            'the database still allows INSERT on audit_events',
            'This connection cannot INSERT into audit_events, so nothing can be recorded at all. The '
                .'revoke was too broad.'
        );
    }

    private function anchorSharesDomainWithApp(): bool
    {
        $anchor = Str::afterLast(Config::string('vault.audit.anchor_address'), '@');

        if ($anchor === '') {
            return false;
        }

        return Str::endsWith(Str::lower((string) parse_url(Config::string('app.url'), PHP_URL_HOST)), Str::lower($anchor));
    }

    /**
     * PHP omits function arguments from exception traces by default (7.4
     * onward). Measured, because the obvious reading of this setting is wrong:
     *
     *   getTraceAsString()  truncates strings to 15 characters and renders
     *                       arrays as `Array`, whatever this setting says — so
     *                       the log file is safe either way.
     *   getTrace()          returns the arguments in full when this is off,
     *                       which is what an error tracker serialises.
     *
     * So this is a check about a tool that is not installed yet, which is why it
     * warns rather than fails. It becomes urgent on the day one is.
     */
    private function argumentsAreHiddenFromTraces(): bool
    {
        return (bool) ini_get('zend.exception_ignore_args');
    }

    private function must(bool $passed, string $good, string $bad): void
    {
        if ($passed) {
            $this->line("  <fg=green>✓</> {$good}");

            return;
        }

        $this->failures++;
        $this->line("  <fg=red>✗</> {$bad}");
    }

    private function should(bool $passed, string $good, string $bad): void
    {
        if ($passed) {
            $this->line("  <fg=green>✓</> {$good}");

            return;
        }

        $this->warnings++;
        $this->line("  <fg=yellow>!</> {$bad}");
    }
}
