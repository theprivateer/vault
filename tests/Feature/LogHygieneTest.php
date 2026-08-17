<?php

use App\Models\Lockbox;
use App\Models\User;
use Database\Factories\EnvelopeFixtures;
use Illuminate\Database\QueryException;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Tests\TestCase;

/**
 * What ends up in a log file (Phase 12, task 5).
 *
 * The leak canary already sweeps the logs, and it covers the path everybody
 * thinks of: a request that is **rejected**. This covers the one nobody does — a
 * request that is *accepted* and then fails underneath, where the framework
 * takes over and writes something the application never composed.
 *
 * That gap was not theoretical. `QueryException` builds its message by
 * substituting the bindings into the statement, so before
 * `App\Support\QueryFailureLog` existed, a failed secret write put the payload
 * ciphertext and the wrapped Item Key into `laravel.log` in full. Every other
 * test passed, and the canary passed, because neither one ever made a
 * well-formed request fail.
 */
function logContents(): string
{
    $contents = '';

    foreach (File::allFiles(storage_path('logs')) as $log) {
        $contents .= $log->getContents();
    }

    return $contents;
}

function forgetLogs(): void
{
    foreach (File::allFiles(storage_path('logs')) as $log) {
        File::delete($log->getPathname());
    }
}

/**
 * Posts a well-formed secret into a lockbox whose table will refuse it.
 *
 * @return array{ciphertext: string, wrapped: string}
 */
function failedSecretWrite(TestCase $test, User $user, Lockbox $lockbox): array
{
    $ciphertext = EnvelopeFixtures::envelope(96);
    $wrapped = EnvelopeFixtures::envelope(48);

    /*
     | One column disappears, so the request passes every check the application
     | makes — including the uniqueness query, which needs the table present —
     | and then fails at the INSERT with the ciphertext already bound as a
     | parameter.
     |
     | Contrived as a cause and entirely ordinary as an effect: a migration
     | running mid-deploy, a lock timeout, a constraint nobody expected.
     | Dropping the whole table is *not* equivalent and was the first attempt at
     | this test — it fails during validation instead, so the only binding is a
     | UUID, and the test passes without exercising the thing it is named for.
     */
    Schema::table('secrets', fn (Blueprint $table) => $table->dropColumn('payload_ct'));

    $test->actingAs($user)
        ->post("/lockboxes/{$lockbox->uuid}/secrets", [
            'uuid' => (string) Str::uuid7(),
            'payload_ct' => $ciphertext,
            'wrapped_item_key' => $wrapped,
            'payload_version' => 2,
        ])
        ->assertServerError();

    return ['ciphertext' => $ciphertext, 'wrapped' => $wrapped];
}

beforeEach(function () {
    config(['logging.default' => 'single']);
    forgetLogs();
});

it('keeps ciphertext and wrapped keys out of the log when a write fails underneath', function () {
    $user = User::factory()->create();
    $written = failedSecretWrite($this, $user, writableLockbox($user));

    $logged = logContents();

    expect($logged)->not->toBeEmpty('The failure should still have been logged.')
        ->and($logged)->not->toContain($written['ciphertext'])
        ->and($logged)->not->toContain($written['wrapped']);
});

/*
 | The self-test, in the leak canary's spirit: prove the danger is real, so the
 | assertion above cannot quietly become a tautology. This builds the message the
 | framework would otherwise have logged and shows it carries the ciphertext —
 | demonstrated rather than assumed.
 */
it('would have leaked, which is why the message is replaced rather than trimmed', function () {
    $ciphertext = EnvelopeFixtures::envelope(96);

    try {
        DB::select('select * from a_table_that_does_not_exist where payload = ?', [$ciphertext]);

        throw new RuntimeException('That query was supposed to fail.');
    } catch (QueryException $exception) {
        // The exception's own message interpolates the binding — this is what
        // the default handler writes, and why QueryFailureLog does not use it.
        expect($exception->getMessage())->toContain($ciphertext)
            ->and($exception->getSql())->not->toContain($ciphertext);
    }
});

it('still logs enough to diagnose the failure', function () {
    $user = User::factory()->create();
    failedSecretWrite($this, $user, writableLockbox($user));

    $logged = logContents();

    // Removing the values must not remove the diagnosis. The statement shape,
    // the driver's reason and a trace are all still there — a log that is safe
    // and useless would simply be turned off.
    // The quotes are JSON-escaped in the context, so match the shape rather
    // than the literal statement.
    // Matched on shape rather than on any one driver's wording: SQLite says
    // "has no column named payload_ct" and Postgres says "column payload_ct of
    // relation secrets does not exist", and both are the same diagnosis.
    expect($logged)->toContain('insert into')
        ->and($logged)->toContain('secrets')
        ->and($logged)->toContain('values (?, ?, ?')
        ->and($logged)->toContain('payload_ct')
        ->and($logged)->toContain('omitted')
        ->and($logged)->toContain('#0 ');
});

it('records no raw address, in the log or in the audit table', function () {
    $user = User::factory()->create();

    // A distinctive address, so its absence is meaningful rather than lucky.
    $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.77'])
        ->actingAs($user)
        ->get('/vaults')
        ->assertOk();

    expect(logContents())->not->toContain('198.51.100.77')
        ->and(DB::table('audit_events')->pluck('ip_hash')->implode(' '))
        ->not->toContain('198.51.100.77');
});

/*
 | Retention is a security control here rather than housekeeping. The log is one
 | of the stores the leak canary sweeps, which is a statement that it is expected
 | to hold nothing worth stealing — and the way that stops being true is a file
 | that has been accumulating since the day the server was built.
 */
it('rotates and expires the log rather than growing one file forever', function () {
    expect(Config::string('logging.channels.daily.driver'))->toBe('daily')
        ->and(Config::integer('logging.channels.daily.max_files'))->toBeGreaterThan(0)
        ->and(Config::integer('logging.channels.daily.max_files'))->toBeLessThanOrEqual(30);
});
