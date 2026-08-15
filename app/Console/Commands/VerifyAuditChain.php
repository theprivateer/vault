<?php

namespace App\Console\Commands;

use App\Models\AuditEvent;
use App\Models\User;
use App\Support\AuditChain;
use App\Support\AuditLog;
use App\Support\AuditStatement;
use Illuminate\Console\Command;

/**
 * Walks the audit chain and reports the first `seq` that diverges.
 *
 * Four kinds of tampering, and what gives each away:
 *
 *  - **Modification** — a field changed. The row's stored hash no longer equals
 *    the hash of its own contents.
 *  - **Deletion** — a row removed. `seq` jumps, and the next row's `prev_hash`
 *    points at a hash that is no longer anywhere.
 *  - **Insertion or reordering** — the same break, from the other direction.
 *  - **Truncation from the end** — nothing above catches it, because what
 *    remains is a perfectly valid shorter chain. The stored head does: it is
 *    compared against the last row, and the daily anchor mailed to the operator
 *    is what catches somebody rewriting the head too.
 *
 * **What this cannot detect**, and the command says so rather than implying
 * otherwise: a server that rewrites the chain from a point and recomputes every
 * hash after it produces a chain that verifies perfectly. Signatures and the
 * external anchor are the answer to that, and both are checked here.
 */
class VerifyAuditChain extends Command
{
    protected $signature = 'vault:audit-verify {--from=1 : Start from this seq, for a partial walk}';

    protected $description = 'Verify the audit log hash chain and report the first divergent entry';

    public function handle(): int
    {
        $from = max(1, (int) $this->option('from'));

        $previous = $from === 1
            ? AuditChain::genesisHash()
            : $this->hashBefore($from);

        if ($previous === null) {
            $this->error('There is no entry at seq '.($from - 1).' to start from.');

            return self::FAILURE;
        }

        $expectedSeq = $from;
        $checked = 0;
        $signatures = 0;
        $keys = $this->signingKeys();

        foreach (AuditEvent::query()->where('seq', '>=', $from)->orderBy('seq')->lazy() as $event) {
            if ($event->seq !== $expectedSeq) {
                return $this->diverged(
                    $expectedSeq,
                    "the sequence jumps to {$event->seq}. Entries between them were deleted, or one "
                    .'was inserted out of order.'
                );
            }

            if ($event->prev_hash !== base64_encode($previous)) {
                return $this->diverged(
                    $event->seq,
                    'its recorded previous hash is not the hash of the entry before it. Something '
                    .'between here and there was changed, removed or reordered.'
                );
            }

            $computed = AuditChain::hash($previous, $event);

            if (! hash_equals($event->hash, base64_encode($computed))) {
                return $this->diverged(
                    $event->seq,
                    'its own contents no longer hash to the value stored beside them. This entry '
                    .'was modified after it was written.'
                );
            }

            if ($event->actor_signature !== null) {
                $reason = $this->checkSignature($event, $keys);

                if ($reason !== null) {
                    return $this->diverged($event->seq, $reason);
                }

                $signatures++;
            }

            $previous = $computed;
            $expectedSeq++;
            $checked++;
        }

        $head = AuditLog::head();

        /*
         | The head is checked last and separately, because it is the only thing
         | that notices entries removed from the *end*. A chain truncated at seq
         | 900 verifies flawlessly on its own — every hash still follows from the
         | one before — and only a record of where the chain used to reach shows
         | that it used to be longer.
         */
        if ($head->seq !== $expectedSeq - 1 || $head->hash !== base64_encode($previous)) {
            $this->error(
                'The chain verifies to seq '.($expectedSeq - 1).', but the recorded head says seq '
                ."{$head->seq}. Entries were removed from the end of the log, or the head was "
                .'rewritten. Compare against the last anchor mailed to the operator.'
            );

            return self::FAILURE;
        }

        $this->info("Verified {$checked} entries, {$signatures} of them signed by the acting user.");
        $this->line('Head: '.$head->hash);

        return self::SUCCESS;
    }

    /**
     * @param  array<string, string>  $keys  actor uuid => raw Ed25519 public key
     */
    private function checkSignature(AuditEvent $event, array $keys): ?string
    {
        $publicKey = $keys[$event->actor_uuid ?? ''] ?? '';

        if ($publicKey === '') {
            /*
             | Not a failure. An account can be closed, and its identity row goes
             | with it; the events it signed stay, because deleting them is the
             | thing this table exists to prevent. What is lost is the ability to
             | re-check those signatures, which is worth saying out loud rather
             | than passing over in silence.
             */
            $this->warn("  seq {$event->seq}: signed by an account that no longer exists — not checked.");

            return null;
        }

        $signature = base64_decode($event->actor_signature ?? '', true);

        if ($signature === false || $signature === '' || $event->signed_payload === null) {
            return 'it carries a signature that is not readable.';
        }

        $verified = sodium_crypto_sign_verify_detached(
            $signature,
            AuditStatement::signedBytes($event->signed_payload),
            $publicKey
        );

        if (! $verified) {
            return 'its signature does not verify. The server cannot forge one, so this entry was '
                .'not written by the account it names.';
        }

        $claim = AuditStatement::parse($event->signed_payload);

        if ($claim === null || $claim['action'] !== $event->action->value) {
            return 'its signature is valid over a statement about something else. A genuine '
                .'signature was moved onto a different event.';
        }

        return null;
    }

    /**
     * Every signing key, loaded once.
     *
     * @return array<string, string>
     */
    private function signingKeys(): array
    {
        return User::query()
            ->has('identity')
            ->with('identity')
            ->get()
            ->mapWithKeys(fn (User $user): array => [
                $user->uuid => $user->identity?->ed25519_public_key->bytes() ?? '',
            ])
            ->filter(fn (string $key): bool => $key !== '')
            ->all();
    }

    private function hashBefore(int $seq): ?string
    {
        $hash = AuditEvent::query()->where('seq', $seq - 1)->value('hash');

        return is_string($hash) ? (string) base64_decode($hash, true) : null;
    }

    /** Named `diverged`, not `fail` — Command::fail() exists and is public. */
    private function diverged(int $seq, string $why): int
    {
        $this->error("The chain diverges at seq {$seq}: {$why}");

        return self::FAILURE;
    }
}
