<?php

use App\Enums\AuditAction;
use App\Models\AuditEvent;
use App\Models\User;
use Illuminate\Mail\Transport\ArrayTransport;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Mail;
use Symfony\Component\Mailer\SentMessage;

/**
 * What actually left the building.
 *
 * `Mail::fake()` cannot see any of this: `MailFake::raw()` is a no-op, so a
 * faked mailer records nothing for a command that sends raw text and every
 * assertion would pass against zero sends. The array transport the test
 * environment already configures records the real message instead, which also
 * makes the *contents* assertable — and the contents are the part worth
 * checking, since this one goes to an inbox outside every control here.
 */
function arrayTransport(): ArrayTransport
{
    $transport = Mail::mailer()->getSymfonyTransport();

    if (! $transport instanceof ArrayTransport) {
        throw new RuntimeException('These tests need MAIL_MAILER=array, which phpunit.xml sets.');
    }

    return $transport;
}

/** @return list<string> */
function sentMessages(): array
{
    $messages = [];

    foreach (arrayTransport()->messages() as $sent) {
        if ($sent instanceof SentMessage) {
            $messages[] = $sent->getOriginalMessage()->toString();
        }
    }

    return $messages;
}

function forgetMessages(): void
{
    arrayTransport()->flush();
}

/**
 * The operator's side of the audit log (Phase 12, task 4).
 *
 * `AccountSecurityAlert` tells an account holder that something happened to
 * *them*, over a channel a takeover does not control. This asks the other
 * question — is something happening to this deployment — and it is read by
 * whoever runs the server rather than by whoever owns the account.
 *
 * The tests are shaped around the two ways an alerting job fails in practice:
 * saying nothing when it should speak, and speaking so often that nobody reads
 * it. The second is why every threshold case has a matching quiet case.
 */
function auditEvents(AuditAction $action, int $count, ?User $actor = null, ?string $ip = null): void
{
    // `seq` is unique and the factory defaults it to 1, since a factory cannot
    // honestly produce a chained entry — the hash depends on the row before it.
    $highest = AuditEvent::query()->max('seq');
    $next = is_numeric($highest) ? (int) $highest : 0;

    for ($i = 1; $i <= $count; $i++) {
        AuditEvent::factory()->create([
            'seq' => $next + $i,
            'action' => $action,
            'actor_uuid' => $actor?->uuid,
            'ip_hash' => $ip ?? 'hash-'.$i,
        ]);
    }
}

beforeEach(function () {
    forgetMessages();
    config(['vault.alerts.address' => 'operator@example.com']);
});

describe('mass reveals', function () {
    it('reports one person revealing more than the threshold', function () {
        config(['vault.alerts.reveals_per_day' => 10]);
        $user = User::factory()->create();
        auditEvents(AuditAction::SecretRevealed, 10, $user);

        expect(Artisan::call('vault:anomalies'))->toBe(0);

        expect(sentMessages())->toHaveCount(1);
    });

    it('stays quiet one below the threshold', function () {
        config(['vault.alerts.reveals_per_day' => 10]);
        auditEvents(AuditAction::SecretRevealed, 9, User::factory()->create());

        expect(Artisan::call('vault:anomalies'))->toBe(0);

        expect(sentMessages())->toBeEmpty();
    });

    /*
     | Counted per actor, not in total. Five people reading ten secrets each is a
     | working day; one person reading fifty is the thing this exists to notice,
     | and a total would not tell them apart.
     */
    it('does not add unrelated people together', function () {
        config(['vault.alerts.reveals_per_day' => 10]);

        foreach (range(1, 5) as $ignored) {
            auditEvents(AuditAction::SecretRevealed, 9, User::factory()->create());
        }

        expect(Artisan::call('vault:anomalies'))->toBe(0);

        expect(sentMessages())->toBeEmpty();
    });
});

describe('failed sign-ins', function () {
    it('reports a burst', function () {
        config(['vault.alerts.failed_sign_ins_per_day' => 5]);
        auditEvents(AuditAction::LoginFailed, 5);

        expect(Artisan::call('vault:anomalies'))->toBe(0);

        expect(sentMessages())->toHaveCount(1);
    });

    it('stays quiet below the threshold', function () {
        config(['vault.alerts.failed_sign_ins_per_day' => 5]);
        auditEvents(AuditAction::LoginFailed, 4);

        expect(Artisan::call('vault:anomalies'))->toBe(0);

        expect(sentMessages())->toBeEmpty();
    });
});

describe('the two that need no threshold', function () {
    it('reports a single use of a recovery kit', function () {
        auditEvents(AuditAction::RecoveryUsed, 1, User::factory()->create());

        expect(Artisan::call('vault:anomalies'))->toBe(0);

        expect(sentMessages())->toHaveCount(1);
    });

    it('reports a single full export', function () {
        auditEvents(AuditAction::AccountExported, 1, User::factory()->create());

        expect(Artisan::call('vault:anomalies'))->toBe(0);

        expect(sentMessages())->toHaveCount(1);
    });
});

describe('the window', function () {
    it('ignores anything older than the window it was asked about', function () {
        $user = User::factory()->create();
        auditEvents(AuditAction::RecoveryUsed, 1, $user);
        AuditEvent::query()->update(['created_at' => now()->subDays(3)]);

        expect(Artisan::call('vault:anomalies'))->toBe(0);

        expect(sentMessages())->toBeEmpty();
    });

    it('finds it again when asked to look further back', function () {
        $user = User::factory()->create();
        auditEvents(AuditAction::RecoveryUsed, 1, $user);
        AuditEvent::query()->update(['created_at' => now()->subDays(3)]);

        expect(Artisan::call('vault:anomalies', ['--hours' => 24 * 7]))->toBe(0);

        expect(sentMessages())->toHaveCount(1);
    });
});

describe('when it cannot report', function () {
    /*
     | The same choice `vault:audit-anchor` makes. A monitoring job that exits
     | zero having had nowhere to send its findings leaves somebody believing
     | they are being watched over.
     */
    it('fails loudly rather than running with nowhere to report', function () {
        config(['vault.alerts.address' => '']);

        expect(Artisan::call('vault:anomalies'))->toBe(1);

        expect(sentMessages())->toBeEmpty();
    });

    it('prints instead of sending when asked, so it can be run by hand', function () {
        config(['vault.alerts.address' => '']);
        auditEvents(AuditAction::RecoveryUsed, 1, User::factory()->create());

        expect(Artisan::call('vault:anomalies', ['--print' => true]))->toBe(0);
        expect(Artisan::output())->toContain('recovery kit');

        expect(sentMessages())->toBeEmpty();
    });
});

it('says a quiet day is a quiet day, and sends nothing', function () {
    expect(Artisan::call('vault:anomalies'))->toBe(0);
    expect(Artisan::output())->toContain('Nothing unusual');

    expect(sentMessages())->toBeEmpty();
});

/*
 | The report reaches an operator's inbox, which is outside every control this
 | application has. Nothing decrypted may go in it — and nothing could, since the
 | server cannot read an item — but the audit metadata it quotes is worth pinning,
 | because that column is the one place a future change could put content.
 */
it('quotes only structural metadata, never anything from a payload', function () {
    $user = User::factory()->create();
    AuditEvent::factory()->create([
        'action' => AuditAction::AccountExported,
        'actor_uuid' => $user->uuid,
        'metadata' => '{"file_count":0,"secret_count":12,"vault_count":2}',
    ]);

    expect(Artisan::call('vault:anomalies', ['--print' => true]))->toBe(0);
    expect(Artisan::output())->toContain('secret_count');
});
