<?php

namespace App\Support;

use App\Enums\AuditAction;
use App\Models\AuditEvent;
use App\Models\Lockbox;
use App\Models\Secret;
use App\Models\ShareLink;
use App\Models\User;
use App\Models\Vault;
use App\Models\VaultFile;
use App\Models\VaultMembership;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Request;
use RuntimeException;

/**
 * Appends to the audit chain.
 *
 * The only writer. Everything else calls `record()` and never touches
 * `audit_events` directly, because the sequence number, the previous hash and
 * the chain head have to move together or not at all — and "or not at all" is
 * why the whole thing happens inside one transaction with the head row locked.
 *
 * **Recording must not be able to fail a request that succeeded.** An audit
 * write that throws after a secret was saved would roll back the secret and
 * report an error for an action that worked; an audit write that silently
 * swallows everything would leave gaps nobody notices. The compromise is
 * deliberate and narrow: the chain write is inside the caller's transaction
 * where there is one, so the two commit together, and the only exceptions this
 * class raises are programming errors — an undeclared metadata key, an
 * unverifiable signature — which are bugs to fix rather than conditions to
 * tolerate.
 */
final class AuditLog
{
    /**
     * How a model is named in `subject_type`.
     *
     * A short slug rather than a class name: class names move with refactors,
     * and a row written in 2026 has to still describe itself in 2031 after the
     * namespace changed. `VaultFile` is `file` here for the same reason the
     * table is `files` — the model's name works around a PHP collision that the
     * log has no reason to inherit.
     *
     * @var array<class-string<Model>, string>
     */
    private const SUBJECTS = [
        User::class => 'user',
        Vault::class => 'vault',
        VaultMembership::class => 'membership',
        Lockbox::class => 'lockbox',
        Secret::class => 'secret',
        VaultFile::class => 'file',
        ShareLink::class => 'sharelink',
    ];

    /**
     * Appends one event.
     *
     * @param  array<string, mixed>  $metadata  structural facts only; see AuditMetadata
     * @param  ?array{signature: string, payload: string}  $signed  for client-originated events
     */
    public static function record(
        AuditAction $action,
        ?Model $subject = null,
        array $metadata = [],
        ?User $actor = null,
        ?array $signed = null,
    ): AuditEvent {
        $actor ??= auth()->user();

        if ($action->isClientOriginated() && $signed === null) {
            throw new RuntimeException(
                "The action [{$action->value}] is reported by the browser and must carry a signature. "
                .'Recording it unsigned would put a claim the server did not witness into the log '
                .'with nothing to distinguish it from one the server invented.'
            );
        }

        /*
         | Settled before the hash is computed, not left to the database. A
         | default from the server clock applied at INSERT time would produce a
         | row whose stored timestamp differs from the one that was hashed, and
         | every verification afterwards would report tampering.
         |
         | Second precision, because that is what the canonical form records —
         | keeping microseconds in the column and dropping them from the hash
         | would be the same bug wearing a different hat.
         */
        $at = now()->startOfSecond();

        return DB::transaction(function () use ($action, $subject, $metadata, $actor, $signed, $at): AuditEvent {
            $head = self::head(locked: true);

            $event = new AuditEvent([
                'seq' => $head->seq + 1,
                'actor_uuid' => $actor?->uuid,
                'action' => $action,
                'subject_type' => $subject ? self::subjectType($subject) : null,
                'subject_uuid' => $subject?->getAttribute('uuid'),
                'metadata' => AuditMetadata::canonicalise($metadata),
                'actor_signature' => $signed['signature'] ?? null,
                'signed_payload' => $signed['payload'] ?? null,
                'ip_hash' => AuditChain::fingerprint(self::clientIp()),
                'user_agent_hash' => AuditChain::fingerprint(self::userAgent()),
                'created_at' => $at,
            ]);

            $hash = AuditChain::hash($head->bytes(), $event);

            $event->prev_hash = $head->hash;
            $event->hash = base64_encode($hash);
            $event->save();

            DB::table('audit_chain')->where('id', 1)->update([
                'seq' => $event->seq,
                'head_hash' => $event->hash,
                'updated_at' => $at,
            ]);

            return $event;
        });
    }

    /**
     * The chain tip, for the daily anchor and for `vault:audit-verify`.
     *
     * `$locked` takes the row lock that serialises sequence allocation. It is a
     * parameter rather than a separate method so there is exactly one place that
     * knows where the head lives — two readers that could drift apart about that
     * is how a chain forks.
     */
    public static function head(bool $locked = false): AuditHead
    {
        $query = DB::table('audit_chain')->where('id', 1);

        if ($locked) {
            $query->lockForUpdate();
        }

        $row = $query->first(['seq', 'head_hash']);

        if (! is_object($row) || ! is_numeric($row->seq ?? null) || ! is_string($row->head_hash ?? null)) {
            throw new RuntimeException(
                'The audit chain head row is missing or malformed. It is created by the migration '
                .'and never deleted; without it there is no way to know where the chain reached.'
            );
        }

        return new AuditHead((int) $row->seq, $row->head_hash);
    }

    private static function subjectType(Model $subject): string
    {
        $type = self::SUBJECTS[$subject::class] ?? null;

        if ($type === null) {
            throw new RuntimeException(
                'No audit subject slug is declared for '.$subject::class.'. Declare one in '
                .'AuditLog::SUBJECTS rather than falling back to the class name, which would tie '
                .'a permanent record to a namespace that will move.'
            );
        }

        return $type;
    }

    /**
     * Null outside an HTTP request, which is the normal case for a scheduled
     * sweep: a console command has no origin, and inventing one — the host's own
     * address, say — would put a fact in the log that was never true.
     *
     * Read straight off the request rather than gated on `runningInConsole()`.
     * The SAPI is `cli` for the whole test suite, so that gate would have made
     * *tested* behaviour differ from production behaviour on every request —
     * the log would have been silently origin-less everywhere it was checked.
     * A genuine console run has no `REMOTE_ADDR`, so the absence answers for
     * itself.
     */
    private static function clientIp(): ?string
    {
        return Request::ip();
    }

    private static function userAgent(): ?string
    {
        return Request::userAgent();
    }
}
