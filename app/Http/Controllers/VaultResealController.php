<?php

namespace App\Http\Controllers;

use App\Enums\AuditAction;
use App\Http\Requests\ResealVaultRequest;
use App\Models\Lockbox;
use App\Models\Secret;
use App\Models\Vault;
use App\Models\VaultFile;
use App\Support\AuditLog;
use App\Support\Ciphertext;
use App\Support\ResealTarget;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\ValidationException;
use Inertia\Inertia;
use Inertia\Response;

/**
 * Moving a vault's payloads onto the current envelope version.
 *
 * Phase 10 introduced envelope v2 and said the old rows would "re-wrap lazily on
 * write". That is true and it is not a migration: in a password manager the
 * payloads nobody edits are the majority and the long-lived ones, so "lazily on
 * write" means "never, for exactly the data that matters most". This is the
 * operation that actually moves them.
 *
 * **The plaintext does not change.** The browser opens each payload, generates a
 * fresh Item Key, and seals the same bytes again at the current version. That is
 * why this is not an edit: no version is archived, `current_version` does not
 * move, `updated_at` is left alone, and the log records one `vault.resealed`
 * rather than a run of updates that never happened.
 *
 * **It is deliberately not atomic**, which is the interesting difference from a
 * re-key. A half-applied rotation strands keys, so that one is all-or-nothing. A
 * half-applied re-seal leaves every row on either v1 or v2, and both open — so
 * this batches, resumes, and can be abandoned half way without leaving anything
 * to repair.
 *
 * **What it cannot reach.** Archived versions are immutable by design
 * (`SecretVersion` throws on update), because an archive that could be rewritten
 * is a rollback channel for a credential somebody rotated *because* it leaked.
 * Those rows stay on v1 until retention ages them out, and `vault:health` counts
 * them separately so the number this operation can drive to zero is a number
 * somebody can actually drive to zero.
 */
class VaultResealController extends Controller
{
    public function create(Request $request, Vault $vault): Response
    {
        $lockboxes = $vault->lockboxes()->orderBy('sort_order')->orderBy('uuid')->get();

        return Inertia::render('vaults/Reseal', [
            'vault' => $vault->toClientArray($this->membershipFor($vault, $request)),
            'lockboxes' => $lockboxes->map(fn (Lockbox $lockbox): array => $lockbox->toClientArray()),

            'secrets' => Secret::query()
                ->whereIn('lockbox_id', $lockboxes->modelKeys())
                ->with(['lockbox', 'linkedLockbox'])
                ->orderBy('uuid')
                ->get()
                ->map(fn (Secret $secret): array => $secret->toClientArray()),

            /*
             | Files are here for one reason: their manifest is a payload like
             | any other, and leaving them out would mean the count never reaches
             | zero. The file *bodies* are not envelopes at all — chunked AES-GCM
             | — so they are outside this entirely.
             */
            'files' => VaultFile::query()
                ->whereIn('lockbox_id', $lockboxes->modelKeys())
                ->with('lockbox')
                ->orderBy('uuid')
                ->get()
                ->map(fn (VaultFile $file): array => $file->toClientArray()),
        ]);
    }

    /**
     * Applies one batch.
     *
     * Every row is a compare-and-swap against the ciphertext the client says it
     * decrypted. **Without that, this operation is a data-loss bug.** A tab that
     * opened the vault an hour ago holds plaintext that may since have been
     * edited elsewhere; re-sealing it would write the old value back under a new
     * envelope, and every check in the system would pass — the ciphertext is
     * well-formed, correctly bound and freshly sealed. Only the bytes it
     * replaced know it is wrong.
     *
     * A row whose ciphertext has moved is skipped rather than reported as an
     * error. It means somebody wrote it since, which means it is already on the
     * current version, which is what this was trying to achieve.
     */
    public function store(ResealVaultRequest $request, Vault $vault): JsonResponse
    {
        $resealed = 0;
        $skipped = 0;

        DB::transaction(function () use ($request, $vault, &$resealed, &$skipped): void {
            $targets = ResealTarget::inVault($vault);

            foreach ($request->array('items') as $item) {
                $submitted = $this->fields($item);
                $target = $targets[$submitted['uuid']] ?? null;

                if ($target === null) {
                    /*
                     | Refused rather than ignored. A submission naming something
                     | outside this vault is a client working from a wrong
                     | picture, and quietly dropping it would let a mistaken
                     | re-seal report success over a set it never touched.
                     */
                    throw ValidationException::withMessages([
                        'items' => 'That set names something that is not in this vault. Nothing was '
                            .'changed; reload and try again.',
                    ]);
                }

                /*
                 | The compare-and-swap, and the reason this operation is not a
                 | data-loss bug. Two guards, and they answer different questions:
                 |
                 |  - the digest says the client decrypted *this* ciphertext, so
                 |    the plaintext it re-sealed is this row's current plaintext;
                 |  - the `where` on `payload_ct` says nothing has moved between
                 |    reading the row above and writing it here.
                 |
                 | Without the first, a tab that opened the vault an hour ago
                 | could write hour-old plaintext back under a fresh envelope,
                 | and every check in the system would pass — the ciphertext is
                 | well formed, correctly bound and freshly sealed. Only the
                 | bytes it replaced would know it was wrong.
                 */
                if (! $target->matches($submitted['previous_digest'])) {
                    $skipped++;

                    continue;
                }

                $applied = DB::table($target->table)
                    ->where('id', $target->id)
                    ->where('payload_ct', $target->payloadCt)
                    ->update([
                        // Query-builder writes bypass the Ciphertext cast, so
                        // base64 is canonicalised by hand.
                        'payload_ct' => Ciphertext::fromBase64($submitted['payload_ct'])->base64,
                        'wrapped_item_key' => Ciphertext::fromBase64($submitted['wrapped_item_key'])->base64,
                        'payload_version' => $submitted['payload_version'],
                        /*
                         | `updated_at` is deliberately absent, and so is
                         | `current_version`. Nothing about this row's contents
                         | changed, and moving either would make a maintenance
                         | pass indistinguishable from somebody having edited
                         | every secret in the vault.
                         */
                    ]);

                $applied === 1 ? $resealed++ : $skipped++;
            }

            /*
             | One event for the batch, with the count — the same shape as a
             | re-key, and for the same reason: the log is read by somebody who
             | was not here, and "re-sealed this vault" without a number leaves
             | them unable to tell a full pass from one that covered two rows.
             */
            AuditLog::record(AuditAction::VaultResealed, $vault, ['count' => $resealed]);
        });

        /*
         | JSON rather than a redirect, because the client drives this in
         | batches and needs each answer before it sends the next. An Inertia
         | visit per batch would re-render and re-decrypt the whole vault
         | between them, which for the large vaults this exists to serve is the
         | difference between one pass and one pass per two hundred rows.
         */
        return response()->json(['applied' => $resealed, 'skipped' => $skipped]);
    }

    /**
     * Narrows one submitted item to the types the rest of this method assumes.
     *
     * The form request has already validated every field; this is what turns
     * "validated" into something static analysis can see, without a cast that
     * would quietly accept an array where a string belongs.
     *
     * @return array{uuid: string, previous_digest: string, payload_ct: string, wrapped_item_key: string, payload_version: int}
     */
    private function fields(mixed $item): array
    {
        $unreadable = fn (): never => throw ValidationException::withMessages([
            'items' => 'That set is not readable.',
        ]);

        if (! is_array($item)) {
            $unreadable();
        }

        $strings = [];

        foreach (['uuid', 'previous_digest', 'payload_ct', 'wrapped_item_key'] as $field) {
            $value = $item[$field] ?? null;

            if (! is_string($value)) {
                $unreadable();
            }

            $strings[$field] = $value;
        }

        $version = $item['payload_version'] ?? null;

        if (! is_int($version)) {
            $unreadable();
        }

        return [
            'uuid' => $strings['uuid'],
            'previous_digest' => $strings['previous_digest'],
            'payload_ct' => $strings['payload_ct'],
            'wrapped_item_key' => $strings['wrapped_item_key'],
            'payload_version' => $version,
        ];
    }
}
