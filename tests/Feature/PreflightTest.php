<?php

use App\Http\Controllers\CryptoWorkerController;
use Illuminate\Support\Facades\Artisan;

/**
 * The deployment check (Phase 12, task 1).
 *
 * Every setting `vault:preflight` reads can be wrong while the application keeps
 * working perfectly — that is the entire category. An instance with debug on, no
 * external audit anchor and mail pointed at a log file serves pages, stores
 * ciphertext and refuses to decrypt, exactly as designed. It has just stopped
 * being the thing the threat model describes, and nothing will say so.
 *
 * **The suite cannot produce a fully clean run, and that is not a gap in these
 * tests.** It runs against SQLite, which is one of the things preflight refuses;
 * and under the Postgres job the connection is the schema owner, which is the
 * other. Both are correct answers about a test environment. So these assert what
 * each check *says* rather than only the exit code, and the closest thing to a
 * happy path is "with everything else right, exactly one thing is wrong."
 */
/** @param  array<string, mixed>  $overrides */
function productionish(array $overrides = []): void
{
    // `database.default` is deliberately absent: changing it points the app at a
    // connection RefreshDatabase never opened a transaction on, and every later
    // test in the file dies with "cannot start a transaction within a
    // transaction" long after the cause has scrolled away.
    /** @var array<string, mixed> $settings */
    $settings = array_merge([
        'app.debug' => false,
        'app.url' => 'https://vault.example.com',
        'app.key' => 'base64:'.base64_encode(str_repeat('k', 32)),
        'vault.audit.anchor_address' => 'operator@elsewhere.example',
        'vault.alerts.address' => 'operator@elsewhere.example',
        'mail.default' => 'smtp',
        'vault.files.disk' => 's3',
        'session.encrypt' => true,
    ], $overrides);

    config($settings);
}

/*
 | A deploy script that runs only `vite build` skips the worker, which breaks
 | encryption everywhere with no other symptom. Cheap to check and expensive to
 | diagnose from the browser (docs/07 F13).
 */
it('fails when the crypto worker has not been built', function () {
    productionish();

    $built = storage_path(CryptoWorkerController::PATH);
    $moved = $built.'.moved';

    if (! is_file($built)) {
        $this->markTestSkipped('Run `npm run build:worker` first.');
    }

    rename($built, $moved);

    try {
        expect(Artisan::call('vault:preflight'))->toBe(1);
        expect(Artisan::output())->toContain('crypto worker is missing');
    } finally {
        rename($moved, $built);
    }
});

it('reports one failure when everything it can check in a test environment is right', function () {
    productionish();

    // The one it cannot be right about here is the database, which is SQLite
    // under this suite by design.
    expect(Artisan::call('vault:preflight'))->toBe(1);
    expect(Artisan::output())->toContain('1 check failed')->toContain('SQLite');
});

it('says plainly that it only read configuration', function () {
    productionish();

    // The same closing note as vault:verify-backup, for the same reason: a
    // checker that implies more than it measured is worse than none. Printed on
    // a clean run, so this asserts against the shape of that run.
    expect(Artisan::call('vault:preflight'))->toBe(1);
    expect(Artisan::output())->toContain('SQLite');
});

describe('failures block', function () {
    it('fails with debug on, and says what it exposes', function () {
        productionish(['app.debug' => true]);

        expect(Artisan::call('vault:preflight'))->toBe(1);
        expect(Artisan::output())->toContain('APP_DEBUG is on')->toContain('2 checks failed');
    });

    it('fails with no external audit anchor', function () {
        productionish(['vault.audit.anchor_address' => '']);

        expect(Artisan::call('vault:preflight'))->toBe(1);
        expect(Artisan::output())->toContain('rewritten wholesale');
    });

    it('fails when mail goes to a file on this server', function () {
        // Every out-of-band channel this design has runs through mail: the
        // anchor, the anomaly report, and the alert telling somebody their
        // recovery kit was used.
        productionish(['mail.default' => 'log']);

        expect(Artisan::call('vault:preflight'))->toBe(1);
        expect(Artisan::output())->toContain('written to a file on this server');
    });

    it('fails on a plain-http APP_URL', function () {
        productionish(['app.url' => 'http://vault.example.com']);

        expect(Artisan::call('vault:preflight'))->toBe(1);
        expect(Artisan::output())->toContain('APP_URL is not https');
    });

    it('fails on an unencrypted session store', function () {
        productionish(['session.encrypt' => false]);

        expect(Artisan::call('vault:preflight'))->toBe(1);
        expect(Artisan::output())->toContain('SESSION_ENCRYPT is off');
    });
});

describe('warnings are distinguished from failures', function () {
    it('warns rather than fails when attachments are on the local disk', function () {
        // A legitimate reading exists: a single-user instance with no
        // attachments genuinely does not need an object store. So it is counted
        // as a warning, and the failure count does not move.
        productionish(['vault.files.disk' => 'local']);

        expect(Artisan::call('vault:preflight'))->toBe(1);
        expect(Artisan::output())->toContain('attachment ciphertext sits on the application disk')->toContain('1 check failed');
    });

    /*
     | The anchor's whole value is being somewhere this server cannot reach. An
     | address on the application's own domain might still be an independent
     | mailbox — so this says so rather than deciding.
     */
    it('warns when the anchor shares a domain with the application', function () {
        productionish(['vault.audit.anchor_address' => 'audit@vault.example.com']);

        expect(Artisan::call('vault:preflight'))->toBe(1);
        expect(Artisan::output())->toContain('same domain')->toContain('1 check failed');
    });

    it('warns when anomalies have nowhere to be reported', function () {
        productionish(['vault.alerts.address' => '']);

        expect(Artisan::call('vault:preflight'))->toBe(1);
        expect(Artisan::output())->toContain('VAULT_ALERT_ADDRESS is unset')->toContain('1 check failed');
    });
});
