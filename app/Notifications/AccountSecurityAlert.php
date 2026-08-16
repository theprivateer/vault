<?php

namespace App\Notifications;

use App\Enums\AuditAction;
use Carbon\CarbonInterface;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;
use RuntimeException;

/**
 * The out-of-band copy of an audit entry the account holder needs to see.
 *
 * The audit log records everything, and an attacker who has taken an account
 * reads that log from inside it. Every in-product signal — the activity feed,
 * the security page, a banner — is behind the credential they now hold. Email is
 * the only channel this application has that a successful takeover does not
 * already control, which is why Phase 2 task 9 asked for it in the same sentence
 * as the log line.
 *
 * Deliberately narrow: two actions, both meaning *somebody may now hold your
 * account*. This is not a feed. An alert that arrives for ordinary activity is
 * an alert people filter, and the one message that matters would be filtered
 * with it.
 *
 * **Nothing here is derived from anything encrypted**, and nothing could be —
 * the server cannot read a vault name, a secret or a note. The message carries
 * an action, a time, and what to do about it. It does not carry the originating
 * IP either, though it easily could: `audit_events` keeps only `ip_hash`, and an
 * address the log declined to store permanently is not one to put in an inbox.
 *
 * Sent synchronously rather than queued. `QUEUE_CONNECTION=database` needs a
 * worker, and a security alert that silently waits in a table on a deployment
 * where nobody started one is worse than no alert: the operator believes the
 * channel exists. The send is a few hundred milliseconds on two rare endpoints,
 * and the caller treats a failure as non-fatal — see RecoveryController.
 */
class AccountSecurityAlert extends Notification
{
    public function __construct(
        public readonly AuditAction $action,
        public readonly CarbonInterface $occurredAt,
    ) {
        if (! in_array($action, self::ALERTABLE, true)) {
            throw new RuntimeException(
                "There is no security alert wording for [{$action->value}]. Add it deliberately "
                .'rather than letting an action fall through to a generic message — the value of '
                .'this channel is that receiving one means something specific.'
            );
        }
    }

    /**
     * The closed set this notification will speak for.
     *
     * @var list<AuditAction>
     */
    public const ALERTABLE = [
        AuditAction::RecoveryUsed,
        AuditAction::PasswordChanged,
    ];

    /** @return list<string> */
    public function via(object $notifiable): array
    {
        return ['mail'];
    }

    public function toMail(object $notifiable): MailMessage
    {
        $at = $this->occurredAt->toDayDateTimeString().' UTC';

        return $this->action === AuditAction::RecoveryUsed
            ? $this->recoveryUsed($at)
            : $this->passwordChanged($at);
    }

    /**
     * The one flow that grants a session without the password.
     *
     * The "if this was not you" half has to be honest, and honest here is bleak:
     * whoever used the kit was made to set a new password immediately, so the
     * account is theirs and the operator cannot take it back — there is no reset
     * and no escrow. Saying "secure your account" would be advice that does not
     * work. What is true is that the vaults are the thing to move.
     */
    private function recoveryUsed(string $at): MailMessage
    {
        return (new MailMessage)
            ->subject('Your recovery kit was used to sign in')
            ->line("Someone signed in to your vault using your recovery kit on {$at}.")
            ->line(
                'If that was you, there is nothing to do. You will have been asked to set a new '
                .'password, and you should have been given a fresh recovery kit — the old one no '
                .'longer works.'
            )
            ->line(
                'If it was not you, act on the assumption that whoever it was now controls the '
                .'account and can read everything in it. They were required to set a new password, '
                .'so you will not be able to sign in, and nobody can reset it for you: the server '
                .'holds no key to your data and never has.'
            )
            ->line(
                'What is worth doing is changing the credentials the vault stored, starting with '
                .'anything shared with other people, and telling whoever runs this server so the '
                .'audit log can be read while it is still fresh.'
            );
    }

    private function passwordChanged(string $at): MailMessage
    {
        return (new MailMessage)
            ->subject('Your vault password was changed')
            ->line("Your vault password was changed on {$at}.")
            ->line('If that was you, no action is needed.')
            ->line(
                'If it was not, someone had both your old password and a signed-in session. Your '
                .'recovery kit still works and is the way back in — use it, then change the '
                .'credentials the vault stored.'
            );
    }
}
