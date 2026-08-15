<?php

use Illuminate\Foundation\Inspiring;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Schedule;

Artisan::command('inspire', function () {
    $this->comment(Inspiring::quote());
})->purpose('Display an inspiring quote');

/*
 | The daily anchor.
 |
 | Mailing the audit chain head to the operator is the only part of the log a
 | compromised server cannot defeat: it can rewrite every row and recompute every
 | hash, and it still cannot reach into yesterday's inbox. See
 | App\Console\Commands\AnchorAuditChain.
 |
 | `withoutOverlapping` because a run that stalls must not leave two anchors
 | quoting different heads for the same day, which would read as evidence of
 | tampering when it was only a slow job.
 */
Schedule::command('vault:audit-anchor')->dailyAt('06:00')->withoutOverlapping();

/*
 | Verification runs on the same schedule but earlier, so that if the chain has
 | broken the operator learns it from a failing job rather than from the anchor
 | quietly recording a head that no longer follows from anything.
 */
Schedule::command('vault:audit-verify')->dailyAt('05:45')->withoutOverlapping();

/*
 | Abandoned uploads and purged file bodies (Phase 6). Overnight, because it
 | deletes and the grace periods are measured in hours and days.
 */
Schedule::command('vault:files-prune')->dailyAt('04:00')->withoutOverlapping();

/*
 | Superseded secret payloads past their vault's retention policy (Phase 8).
 | Before the file sweep, and before the audit jobs, so that the history it
 | removes is recorded on the same day it goes rather than the next one.
 */
Schedule::command('vault:history-prune')->dailyAt('03:45')->withoutOverlapping();
