<?php

use App\Enums\AuditAction;
use App\Models\User;
use App\Notifications\AccountSecurityAlert;
use Database\Factories\UserFactory;
use Database\Factories\UserKeyWrapFactory;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\RateLimiter;

/**
 * The out-of-band half of the audit log (Phase 2, task 9).
 *
 * Everything in the product that could tell a user their account was taken sits
 * behind the credential the taker now holds — the activity feed included, which
 * is where the recovery entry was written to be read. Email is the only channel
 * here that a successful takeover does not also control.
 */
beforeEach(function () {
    RateLimiter::clear('recover:'.sha1('127.0.0.1'));
});

describe('recovery', function () {
    it('mails the account holder when the recovery kit is used', function () {
        Notification::fake();

        $user = recoverableAccount();

        $this->postJson('/recover', [
            'email' => 'ada@example.com',
            'recovery_auth_key' => UserKeyWrapFactory::RECOVERY_AUTH_KEY,
        ])->assertOk();

        Notification::assertSentTo(
            $user,
            AccountSecurityAlert::class,
            fn (AccountSecurityAlert $alert): bool => $alert->action === AuditAction::RecoveryUsed,
        );
    });

    it('sends nothing when the kit does not match', function () {
        Notification::fake();

        recoverableAccount();

        $this->postJson('/recover', [
            'email' => 'ada@example.com',
            'recovery_auth_key' => base64_encode(random_bytes(32)),
        ])->assertStatus(422);

        /*
         | A failed attempt must be silent, and this is not just noise control.
         | An alert on every wrong guess is a way to flood somebody's inbox by
         | typing their address, and — worse — it confirms to the sender that the
         | address has an account, which is the enumeration SR6 forbids.
         */
        Notification::assertNothingSent();
    });

    it('does not follow the recovery alert with a password-change one', function () {
        Notification::fake();

        $user = recoverableAccount();

        $this->postJson('/recover', [
            'email' => 'ada@example.com',
            'recovery_auth_key' => UserKeyWrapFactory::RECOVERY_AUTH_KEY,
        ])->assertOk();

        $this->postJson('/account/password', passwordChangePayload())->assertOk();

        // The forced change is this flow's own next step. Reporting it back
        // would be telling the user what they were just made to do, and teaching
        // them that these messages are noise.
        Notification::assertSentTimes(AccountSecurityAlert::class, 1);
    });

    it('recovers the account even when mail is broken', function () {
        /*
         | The ordering guarantee. By the time the alert is sent the session is
         | already granted, so a mail host that is down must not turn a
         | locked-out user away at the last step — that would make a broken SMTP
         | configuration into a broken recovery flow, and recovery has no second
         | way through.
         */
        Mail::shouldReceive('send')->andThrow(new RuntimeException('smtp is down'));

        recoverableAccount();

        $this->postJson('/recover', [
            'email' => 'ada@example.com',
            'recovery_auth_key' => UserKeyWrapFactory::RECOVERY_AUTH_KEY,
        ])->assertOk()->assertJsonStructure(['wrappedUserKey']);

        $this->assertAuthenticated();
    });
});

describe('password change', function () {
    it('mails the account holder on an ordinary password change', function () {
        Notification::fake();

        $user = recoverableAccount();

        $this->actingAs($user)
            ->postJson('/account/password', passwordChangePayload([
                'current_auth_key' => UserFactory::AUTH_KEY,
            ]))
            ->assertOk();

        Notification::assertSentTo(
            $user,
            AccountSecurityAlert::class,
            fn (AccountSecurityAlert $alert): bool => $alert->action === AuditAction::PasswordChanged,
        );
    });

    it('sends nothing when the current password is wrong', function () {
        Notification::fake();

        $user = recoverableAccount();

        $this->actingAs($user)
            ->postJson('/account/password', passwordChangePayload([
                'current_auth_key' => base64_encode(random_bytes(32)),
            ]))
            ->assertStatus(422);

        Notification::assertNothingSent();
    });
});

describe('the message', function () {
    it('carries the action and the time, and no submitted material', function () {
        $user = User::factory()->create(['email' => 'ada@example.com']);
        $at = now();

        $alert = new AccountSecurityAlert(AuditAction::RecoveryUsed, $at);
        $mail = $alert->toMail($user);

        // The rendered message rather than its parts, because what is asserted
        // below is about what actually lands in the inbox.
        $body = (string) $mail->render();

        expect($mail->subject)->toContain('recovery kit')
            ->and($body)->toContain($at->toDayDateTimeString());

        /*
         | Nothing encrypted could reach here even by accident — the server
         | cannot open a payload — but the message must not carry the
         | originating address either. `audit_events` keeps only `ip_hash`, and
         | an address the log deliberately declined to store is not one to put
         | into an inbox.
         */
        expect($body)->not->toContain('127.0.0.1');
    });

    it('refuses an action it has no wording for', function () {
        expect(fn () => new AccountSecurityAlert(AuditAction::LoggedIn, now()))
            ->toThrow(RuntimeException::class);
    });
});
