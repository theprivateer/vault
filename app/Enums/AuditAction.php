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
     * Ownership transfer (Phase 5, task 9).
     *
     * Recorded against the *recipient's* membership rather than the vault,
     * because the row that changed meaning is theirs, and it names who received
     * the vault without putting a second copy of their handle in `metadata`.
     *
     * The outgoing owner's demotion to editor is not a second event. It is the
     * deterministic other half of this one — a vault has exactly one owner — and
     * the actor on this row is the person it happened to.
     */
    case VaultOwnershipTransferred = 'vault.ownership_transferred';

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

    /**
     * Version history (Phase 8).
     *
     * A restore is recorded separately from an ordinary edit even though the
     * server performs exactly the same write, because the two mean different
     * things to somebody reading the log afterwards: one is a change, and the
     * other is somebody reaching back for a value that was deliberately
     * replaced. That distinction is the whole reason for reading a history.
     *
     * Purging is destructive and deliberate; pruning is the retention policy
     * running on a timer. Both remove history, and conflating them would make
     * it impossible to tell "somebody erased this" from "it aged out".
     */
    case SecretRestored = 'secret.restored';
    case SecretHistoryPurged = 'secret.history_purged';
    case SecretHistoryPruned = 'secret.history_pruned';

    case VaultRetentionChanged = 'vault.retention_changed';

    case FileCreated = 'file.created';
    case FileUploaded = 'file.uploaded';
    case FileDownloaded = 'file.downloaded';
    case FileDeleted = 'file.deleted';
    case FilePruned = 'file.pruned';

    /**
     * One-time share links (Phase 9).
     *
     * `ShareLinkViewed` is the only event in the log with no actor and no
     * possibility of one: the person who opened it has no account, and the
     * server knows nothing about them beyond a keyed hash of their address. It
     * is recorded anyway, because "this credential left the building, and when"
     * is exactly what somebody investigating needs, and it is the only trace
     * there will ever be.
     */
    case ShareLinkCreated = 'sharelink.created';
    case ShareLinkViewed = 'sharelink.viewed';
    case ShareLinkRevoked = 'sharelink.revoked';
    case ShareLinkExpired = 'sharelink.expired';

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
            self::VaultOwnershipTransferred => 'handed this vault over, and became an editor of it',
            self::VaultUnlocked => 'unlocked this vault',
            self::LockboxCreated => 'created a lockbox',
            self::LockboxUpdated => 'renamed a lockbox',
            self::LockboxDeleted => 'deleted a lockbox',
            self::SecretCreated => 'added a secret',
            self::SecretUpdated => 'changed a secret',
            self::SecretDeleted => 'deleted a secret',
            self::SecretRevealed => 'revealed a secret',
            self::SecretRestored => 'restored an earlier version of a secret',
            self::SecretHistoryPurged => 'erased a secret’s history',
            self::SecretHistoryPruned => 'had history removed by the retention policy',
            self::VaultRetentionChanged => 'changed how long this vault keeps history',
            self::FileCreated => 'started a file upload',
            self::FileUploaded => 'finished a file upload',
            self::FileDownloaded => 'downloaded a file',
            self::FileDeleted => 'deleted a file',
            self::FilePruned => 'was swept by the file sweeper',
            self::ShareLinkCreated => 'created a one-time link to a secret',
            self::ShareLinkViewed => 'was opened by someone with the link',
            self::ShareLinkRevoked => 'withdrew a one-time link',
            self::ShareLinkExpired => 'was swept after expiring',
            self::MembershipGranted => 'shared this vault',
            self::MembershipAccepted => 'accepted access to this vault',
            self::MembershipRevoked => 'revoked access to this vault',
        };
    }
}
