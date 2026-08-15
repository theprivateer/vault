<?php

namespace App\Enums;

/**
 * Everything the audit log can record.
 *
 * A closed set rather than a free string, for the same reason `AAD_CONTEXTS` is
 * one: a typo would silently create a second category that nothing queries and
 * no reviewer notices, and the failure would only surface when somebody went
 * looking for events that were never grouped under the name they searched for.
 *
 * The names are `subject.verb`, past tense, because a log is a record of what
 * happened rather than a queue of what to do.
 */
enum AuditAction: string
{
    // Account lifecycle. `LoginFailed` is the one event with no actor, since
    // the whole point is that the address may belong to nobody.
    case Registered = 'auth.registered';
    case LoggedIn = 'auth.logged_in';
    case LoginFailed = 'auth.login_failed';
    case LoggedOut = 'auth.logged_out';
    case PasswordChanged = 'auth.password_changed';
    case RecoveryUsed = 'auth.recovery_used';
    case RecoveryKitIssued = 'auth.recovery_kit_issued';
    case TotpEnabled = 'auth.totp_enabled';
    case TotpDisabled = 'auth.totp_disabled';

    case VaultCreated = 'vault.created';
    case VaultUpdated = 'vault.updated';
    case VaultDeleted = 'vault.deleted';
    case VaultRekeyed = 'vault.rekeyed';

    /**
     * Reported by the browser, not observed here.
     *
     * The server never learns that a vault was unlocked — unwrapping happens in
     * a Worker and nothing about it crosses the network. Without the client
     * saying so, the log would show a login and then a gap, and the most
     * security-relevant moment in a session would be the one it could not see.
     */
    case VaultUnlocked = 'vault.unlocked';

    case LockboxCreated = 'lockbox.created';
    case LockboxUpdated = 'lockbox.updated';
    case LockboxDeleted = 'lockbox.deleted';

    case SecretCreated = 'secret.created';
    case SecretUpdated = 'secret.updated';
    case SecretDeleted = 'secret.deleted';

    /**
     * Also client-reported, and the single most useful line in the log.
     *
     * "Which credentials did that session actually look at" is the first
     * question after any compromise, and the server cannot answer it: a page
     * load fetches a whole vault's ciphertext whether the user opens one item
     * or none. Only the browser knows what was revealed.
     */
    case SecretRevealed = 'secret.revealed';

    case FileCreated = 'file.created';
    case FileUploaded = 'file.uploaded';
    case FileDownloaded = 'file.downloaded';
    case FileDeleted = 'file.deleted';
    case FilePruned = 'file.pruned';

    case MembershipGranted = 'membership.granted';
    case MembershipAccepted = 'membership.accepted';
    case MembershipRevoked = 'membership.revoked';

    /**
     * Whether this event is reported by the browser rather than observed here.
     *
     * Client-originated events must carry an Ed25519 signature, because they are
     * the only claims in the log that the server did not witness — and, being
     * unwitnessed, are the only ones it has any business being unable to forge.
     */
    public function isClientOriginated(): bool
    {
        return in_array($this, [self::VaultUnlocked, self::SecretRevealed], true);
    }

    /** A short, human sentence for the activity views. */
    public function describe(): string
    {
        return match ($this) {
            self::Registered => 'created their account',
            self::LoggedIn => 'signed in',
            self::LoginFailed => 'failed to sign in',
            self::LoggedOut => 'signed out',
            self::PasswordChanged => 'changed their password',
            self::RecoveryUsed => 'signed in with their recovery kit',
            self::RecoveryKitIssued => 'issued a new recovery kit',
            self::TotpEnabled => 'turned on two-factor authentication',
            self::TotpDisabled => 'turned off two-factor authentication',
            self::VaultCreated => 'created this vault',
            self::VaultUpdated => 'renamed this vault',
            self::VaultDeleted => 'deleted this vault',
            self::VaultRekeyed => 'rotated this vault’s key',
            self::VaultUnlocked => 'unlocked this vault',
            self::LockboxCreated => 'created a lockbox',
            self::LockboxUpdated => 'renamed a lockbox',
            self::LockboxDeleted => 'deleted a lockbox',
            self::SecretCreated => 'added a secret',
            self::SecretUpdated => 'changed a secret',
            self::SecretDeleted => 'deleted a secret',
            self::SecretRevealed => 'revealed a secret',
            self::FileCreated => 'started a file upload',
            self::FileUploaded => 'finished a file upload',
            self::FileDownloaded => 'downloaded a file',
            self::FileDeleted => 'deleted a file',
            self::FilePruned => 'was swept by the file sweeper',
            self::MembershipGranted => 'shared this vault',
            self::MembershipAccepted => 'accepted access to this vault',
            self::MembershipRevoked => 'revoked access to this vault',
        };
    }
}
