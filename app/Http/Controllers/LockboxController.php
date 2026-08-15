<?php

namespace App\Http\Controllers;

use App\Enums\AuditAction;
use App\Http\Requests\StoreLockboxRequest;
use App\Http\Requests\UpdateItemRequest;
use App\Models\Lockbox;
use App\Models\Secret;
use App\Models\Vault;
use App\Models\VaultFile;
use App\Support\AuditLog;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Inertia\Inertia;
use Inertia\Response;

/**
 * Lockboxes: a group of secrets inside a vault.
 *
 * The parent vault comes from the route and is authorised as a record. No
 * method here reads a vault identifier out of the request body — that is the
 * shape of an IDOR, and the way to not have one is to never accept the input.
 */
class LockboxController extends Controller
{
    /**
     * One lockbox, delivered with the rest of its vault around it.
     *
     * Both the lockbox list and the secret list are vault-wide rather than
     * scoped to this lockbox, which is not an accident of convenience:
     *
     *  - The browser has to render a *linked* lockbox by name, and it can only
     *    do that by decrypting that lockbox's payload. The server cannot
     *    resolve the name on its behalf.
     *  - Search is client-side (D5), so it works over the vault the user is in,
     *    not the folder they happen to have open. Sending the same shape from
     *    both pages means moving between them re-uses the decrypted store
     *    instead of paying for the whole vault again.
     */
    public function show(Request $request, Lockbox $lockbox): Response
    {

        $siblings = $lockbox->vault->lockboxes()
            ->withCount('secrets')
            ->orderBy('sort_order')
            ->orderBy('uuid')
            ->get();

        $secrets = Secret::query()
            ->whereIn('lockbox_id', $siblings->modelKeys())
            ->with(['lockbox', 'linkedLockbox'])
            /*
             | One aggregate rather than a query per row, so a secret can offer
             | a history link only where there is history. The count is all the
             | page needs — the versions themselves are fetched by the page that
             | actually shows them, since each one costs a decrypt.
             */
            ->withCount('versions')
            ->orderBy('sort_order')
            ->orderBy('uuid')
            ->get()
            ->map(fn (Secret $secret): array => $secret->toClientArray());

        /*
         | Files are scoped to this lockbox, unlike the secrets above.
         |
         | Secrets are vault-wide because search is client-side and has to reach
         | the whole vault. An attachment is not searchable — its manifest holds
         | a filename and a hash, not text anybody types — so sending every
         | file in the vault would cost a decrypt per manifest for a list nobody
         | is looking at.
         */
        $files = $lockbox->files()
            ->whereNotNull('uploaded_at')
            ->orderBy('sort_order')
            ->orderBy('uuid')
            ->get();

        return Inertia::render('lockboxes/Show', [
            /*
             | The whole vault record, not just its identifier: the browser
             | cannot open anything here without first unsealing the Vault Key
             | from this user's membership row.
             */
            'vault' => $lockbox->vault->toClientArray($this->membershipFor($lockbox->vault, $request)),
            'lockbox' => $lockbox->toClientArray(),
            'secrets' => $secrets,
            'lockboxes' => $siblings->map(fn (Lockbox $sibling): array => $sibling->toClientArray()),
            'files' => $files->map(fn (VaultFile $file): array => $file->toClientArray()),
            /*
             | The bounds a share link may be created within (Phase 9). Sent so
             | the form can offer a slider that cannot produce a request the
             | server will refuse — the validation is still the authority, this
             | is only what the interface shows.
             */
            'shareLimits' => [
                'defaultHours' => Config::integer('vault.share_links.default_hours'),
                'maxHours' => Config::integer('vault.share_links.max_hours'),
                'maxViews' => Config::integer('vault.share_links.max_views'),
            ],
        ]);
    }

    public function store(StoreLockboxRequest $request, Vault $vault): RedirectResponse
    {

        $lockbox = $vault->lockboxes()->create([
            'uuid' => $request->string('uuid')->toString(),
            'payload_ct' => $request->string('payload_ct')->toString(),
            'wrapped_item_key' => $request->string('wrapped_item_key')->toString(),
            'payload_version' => $request->integer('payload_version'),
            'sort_order' => $request->integer('sort_order'),
        ]);

        AuditLog::record(AuditAction::LockboxCreated, $lockbox);

        return back();
    }

    public function update(UpdateItemRequest $request, Lockbox $lockbox): RedirectResponse
    {

        $lockbox->update([
            'payload_ct' => $request->string('payload_ct')->toString(),
            'wrapped_item_key' => $request->string('wrapped_item_key')->toString(),
            'payload_version' => $request->integer('payload_version'),
        ]);

        AuditLog::record(AuditAction::LockboxUpdated, $lockbox);

        return back();
    }

    public function destroy(Lockbox $lockbox): RedirectResponse
    {
        /*
         | The count is recorded because deleting a lockbox takes its secrets
         | with it, and "deleted a lockbox" alone understates that. A count is
         | structural; the names of what went are not, and do not appear.
         */
        $count = $lockbox->secrets()->count();

        $lockbox->delete();

        AuditLog::record(AuditAction::LockboxDeleted, $lockbox, ['count' => $count]);

        return to_route('vaults.show', $lockbox->vault);
    }
}
