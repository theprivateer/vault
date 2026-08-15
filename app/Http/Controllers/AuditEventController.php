<?php

namespace App\Http\Controllers;

use App\Enums\AuditAction;
use App\Models\AuditEvent;
use App\Models\Secret;
use App\Models\User;
use App\Models\Vault;
use App\Models\VaultFile;
use App\Support\AuditLog;
use App\Support\AuditStatement;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Illuminate\Validation\Rule;
use Illuminate\Validation\ValidationException;
use Inertia\Inertia;
use Inertia\Response;

/**
 * Events the browser reports, and the views that read the log back.
 *
 * Only two actions can arrive here, and both are things the server genuinely
 * cannot observe: a vault being unlocked and a secret being revealed. Everything
 * else in the log is written where it happens, because an event the server
 * witnessed has no business being taken on the client's word.
 */
class AuditEventController extends Controller
{
    /**
     * Records a signed client-side event.
     *
     * **The signature is checked here even though this server serves the public
     * key it checks against**, which is ordinarily the definition of asking the
     * forger whether the forgery is genuine. It is worth doing anyway, for a
     * reason that is about data rather than attackers: an unverifiable signature
     * accepted now is a permanent failure in `vault:audit-verify` later, in a
     * table that by design can never be corrected. Catching it at the door turns
     * a client bug into a 422 instead of a log that reports tampering forever.
     *
     * The real check happens in `vault:audit-verify`, run by an operator who can
     * compare against an anchor the server never held.
     */
    public function store(Request $request): JsonResponse
    {
        $request->validate([
            'action' => ['required', 'string', Rule::in(self::reportable())],
            'subject_uuid' => ['required', 'uuid'],
            'payload' => ['required', 'string', 'max:512'],
            'signature' => ['required', 'string', 'max:128'],
        ]);

        $action = AuditAction::from($request->string('action')->toString());
        $subjectUuid = $request->string('subject_uuid')->toString();
        $payload = $request->string('payload')->toString();
        $signature = $request->string('signature')->toString();

        $user = $this->currentUser($request);
        $subject = $this->resolveSubject($action, $subjectUuid, $user);

        $reason = AuditStatement::reject($user, $action, $subjectUuid, $payload, $signature);

        if ($reason !== null) {
            throw ValidationException::withMessages(['signature' => $reason]);
        }

        AuditLog::record($action, $subject, [], $user, [
            'signature' => $signature,
            'payload' => $payload,
        ]);

        return response()->json(['ok' => true]);
    }

    /**
     * What has happened in one vault.
     *
     * Scoped to the vault, its lockboxes, its secrets, its files and its
     * memberships — the subject is a UUID rather than a foreign key, so the set
     * is assembled rather than joined. That is the cost of records outliving the
     * things they describe, and it is the right way round.
     */
    public function vault(Vault $vault): Response
    {
        $lockboxIds = $vault->lockboxes()->withTrashed()->pluck('id')->all();

        $subjects = [
            $vault->uuid,
            ...$this->uuids($vault->lockboxes()->withTrashed()->pluck('uuid')->all()),
            ...$this->uuids($vault->memberships()->pluck('uuid')->all()),
            ...$this->uuids(Secret::withTrashed()->whereIn('lockbox_id', $lockboxIds)->pluck('uuid')->all()),
            ...$this->uuids(VaultFile::withTrashed()->whereIn('lockbox_id', $lockboxIds)->pluck('uuid')->all()),
        ];

        $events = AuditEvent::query()
            ->aboutAny($subjects)
            ->with('actor')
            ->orderByDesc('seq')
            ->limit(Config::integer('vault.audit.feed_limit'))
            ->get();

        return Inertia::render('vaults/Activity', [
            'vault' => ['uuid' => $vault->uuid],
            'events' => $events->map(fn (AuditEvent $event): array => $event->toClientArray()),
        ]);
    }

    /**
     * What this account has done, wherever it did it.
     *
     * The answer to "am I the only one using this account", and the page a
     * recovery-kit sign-in nobody remembers shows up on. Scoped by actor rather
     * than by subject, so it includes events about vaults the user has since
     * been removed from — being removed from a vault does not unmake what you
     * did in it.
     */
    public function mine(Request $request): Response
    {
        $events = AuditEvent::query()
            ->where('actor_uuid', $this->currentUser($request)->uuid)
            ->with('actor')
            ->orderByDesc('seq')
            ->limit(Config::integer('vault.audit.feed_limit'))
            ->get();

        return Inertia::render('account/Activity', [
            'events' => $events->map(fn (AuditEvent $event): array => $event->toClientArray()),
        ]);
    }

    /**
     * Narrows a plucked column to strings.
     *
     * `pluck` is typed as mixed and these values go into a `whereIn` over a
     * uuid column, so anything that is not a string is dropped rather than
     * coerced — a stray null coerced to `''` would widen the query rather than
     * narrow it.
     *
     * @param  array<array-key, mixed>  $values
     * @return list<string>
     */
    private function uuids(array $values): array
    {
        return array_values(array_filter($values, is_string(...)));
    }

    /**
     * @return list<string>
     */
    private static function reportable(): array
    {
        return array_values(array_map(
            fn (AuditAction $action): string => $action->value,
            array_filter(AuditAction::cases(), fn (AuditAction $action): bool => $action->isClientOriginated()),
        ));
    }

    /**
     * Resolves the subject, and refuses one the user cannot reach.
     *
     * Without this, any authenticated account could report having revealed any
     * secret in the system — a way to write somebody else's UUID into a
     * permanent record, which is a small but real form of log poisoning. The
     * policies decide, as everywhere else.
     */
    private function resolveSubject(AuditAction $action, string $uuid, User $user): Vault|Secret
    {
        $subject = $action === AuditAction::VaultUnlocked
            ? Vault::query()->where('uuid', $uuid)->first()
            : Secret::query()->where('uuid', $uuid)->first();

        if ($subject === null || $user->cannot('view', $subject)) {
            // 422 rather than 404: the request is already inside a policy-checked
            // session, and a validation error keeps the client's reporting path
            // uniform. Nothing here confirms existence — an unreachable subject
            // and a missing one give the same message.
            throw ValidationException::withMessages([
                'subject_uuid' => 'That is not something this account can report an event about.',
            ]);
        }

        return $subject;
    }
}
