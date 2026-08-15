<?php

namespace App\Http\Controllers;

use App\Enums\AuditAction;
use App\Http\Requests\StoreSecretRequest;
use App\Http\Requests\UpdateSecretRequest;
use App\Models\Lockbox;
use App\Models\Secret;
use App\Support\AuditLog;
use App\Support\Ciphertext;
use App\Support\HistoryRetention;
use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\ValidationException;

/**
 * Secrets.
 *
 * In 2017 this controller decrypted a secret's key and value on every read and
 * sent the plaintext to the browser. There is no equivalent here, and no way to
 * write one: `Ciphertext` has no decrypt method and the server holds no key.
 */
class SecretController extends Controller
{
    public function store(StoreSecretRequest $request, Lockbox $lockbox): RedirectResponse
    {

        $secret = $lockbox->secrets()->create([
            'uuid' => $request->string('uuid')->toString(),
            'payload_ct' => $request->string('payload_ct')->toString(),
            'wrapped_item_key' => $request->string('wrapped_item_key')->toString(),
            'payload_version' => $request->integer('payload_version'),
            'current_version' => Secret::INITIAL_VERSION,
            'sort_order' => $request->integer('sort_order'),
            'linked_lockbox_id' => $this->linkedLockboxId($request, $lockbox),
        ]);

        AuditLog::record(AuditAction::SecretCreated, $secret);

        return back();
    }

    /**
     * Re-encrypts a secret, refusing if someone else got there first.
     *
     * **Why the server has to arbitrate this at all.** Nothing here can merge
     * two edits: the two payloads are ciphertext under different item keys, and
     * merging them would mean reading them. The only options are to detect the
     * collision or to lose one silently, and losing a password silently is the
     * kind of bug people discover months later when they need it.
     *
     * `current_version` is the token, compared inside the `where` of the update
     * itself rather than read and then checked. A read-then-write leaves a
     * window between the two in which the other writer commits, which on a
     * concurrent edit — the exact case being defended — is when it is most
     * likely to matter.
     *
     * **Not HTTP 409.** Inertia reserves 409 for its own asset-version
     * protocol and answers one with a hard page reload, which would throw away
     * the user's unsaved edit while telling them nothing. A validation error
     * puts the message beside the form with the text still in it.
     */
    public function update(UpdateSecretRequest $request, Secret $secret): RedirectResponse
    {
        $expected = $request->integer('expected_version');
        $restoredFrom = $request->integer('restored_from');

        DB::transaction(function () use ($request, $secret, $expected, $restoredFrom): void {
            /*
             | Canonicalised by hand, because a query-builder update writes
             | columns without running the model's casts — and the Ciphertext
             | cast is where base64 is normalised and size-checked. Passing the
             | request string straight through would store whatever padding the
             | client happened to send and skip the cap.
             */
            $written = Secret::query()
                ->whereKey($secret->getKey())
                ->where('current_version', $expected)
                ->update([
                    'payload_ct' => Ciphertext::fromBase64(
                        $request->string('payload_ct')->toString()
                    )->base64,
                    'wrapped_item_key' => Ciphertext::fromBase64(
                        $request->string('wrapped_item_key')->toString()
                    )->base64,
                    'payload_version' => $request->integer('payload_version'),
                    'linked_lockbox_id' => $this->linkedLockboxId($request, $secret->lockbox),
                    'current_version' => $expected + 1,
                    'updated_at' => now(),
                ]);

            if ($written === 0) {
                throw ValidationException::withMessages([
                    'expected_version' => 'This secret was changed somewhere else after you opened it. '
                        .'Reload to see the current value — your edit has not been saved, and neither '
                        .'version has been lost.',
                ]);
            }

            $this->archive($request, $secret, $expected);

            AuditLog::record(
                $restoredFrom > 0 ? AuditAction::SecretRestored : AuditAction::SecretUpdated,
                $secret,
                $restoredFrom > 0
                    ? ['version' => $expected + 1, 'restored_from' => $restoredFrom]
                    : ['version' => $expected + 1],
            );
        });

        return back();
    }

    /**
     * Keeps the payload this write replaced.
     *
     * **The archived ciphertext is not the old column.** The browser re-sealed
     * the outgoing plaintext under a fresh Item Key bound to
     * `secret.version.payload` at the version row's own UUID, and that is what
     * lands here. Copying `secrets.payload_ct` across would have been free and
     * would have been a hole: the copy carries associated data binding it to
     * `secret.payload` at the secret's UUID, which is byte-for-byte the binding
     * the live column has, so any archived version could be written back over
     * the live row and would verify. Rolling a rotated credential back to the
     * one that leaked is the attack history creates, and the distinct context is
     * what closes it.
     *
     * The insert happens after the guarded update rather than before, so that a
     * write losing the concurrency race leaves no orphan behind. Both are inside
     * one transaction, so a unique-key collision on `(secret_id, version)` — two
     * writers somehow past the guard — rolls the whole edit back rather than
     * recording a second, contradictory payload for one version number.
     */
    private function archive(UpdateSecretRequest $request, Secret $secret, int $version): void
    {
        $vault = $secret->lockbox->vault;

        if ($vault->historyMaxVersions() > 0) {
            $secret->versions()->create([
                'uuid' => $request->string('version_uuid')->toString(),
                'version' => $version,
                'payload_ct' => $request->string('version_payload_ct')->toString(),
                'wrapped_item_key' => $request->string('version_wrapped_item_key')->toString(),
                'payload_version' => $request->integer('version_payload_version'),
                'created_by' => $request->user()?->getKey(),
            ]);
        }

        HistoryRetention::trimToCount($secret, $vault);
    }

    public function destroy(Secret $secret): RedirectResponse
    {

        $secret->delete();

        AuditLog::record(AuditAction::SecretDeleted, $secret);

        return back();
    }

    /**
     * Resolves the lockbox-as-a-value link, scoped to the same vault.
     *
     * The request rules already reject anything outside the vault. Re-scoping
     * the lookup means that even if that rule were ever loosened, the query
     * itself cannot reach across a vault boundary.
     */
    private function linkedLockboxId(StoreSecretRequest|UpdateSecretRequest $request, Lockbox $lockbox): ?int
    {
        $uuid = $request->string('linked_lockbox_uuid')->toString();

        if ($uuid === '') {
            return null;
        }

        $id = Lockbox::query()
            ->where('vault_id', $lockbox->vault_id)
            ->where('uuid', $uuid)
            ->value('id');

        return is_int($id) ? $id : null;
    }
}
