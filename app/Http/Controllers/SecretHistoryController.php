<?php

namespace App\Http\Controllers;

use App\Enums\AuditAction;
use App\Models\Secret;
use App\Models\SecretVersion;
use App\Support\AuditLog;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Inertia\Inertia;
use Inertia\Response;

/**
 * Reading and erasing a secret's history.
 *
 * There is deliberately no *write* here. A version is created only as the other
 * half of an edit, inside the same transaction as the update that superseded it
 * (see SecretController::archive), because a history that can be appended to
 * independently of the thing it describes is a history that can be made to say
 * something that did not happen.
 *
 * Restoring is likewise not here. Restoring is an ordinary update carrying an
 * old payload, so it goes through the same optimistic-concurrency guard as any
 * other edit and archives whatever it replaces. That is what "never
 * destructive" means in practice, and it is a property of routing it through
 * the existing path rather than a rule this controller would have to remember.
 */
class SecretHistoryController extends Controller
{
    /**
     * Every superseded payload of one secret, still encrypted.
     *
     * The vault record comes along because the browser cannot open any of it
     * without unsealing the Vault Key from this user's membership row first —
     * the same reason the lockbox page carries it.
     */
    public function index(Request $request, Secret $secret): Response
    {
        $vault = $secret->lockbox->vault;

        $versions = $secret->versions()
            ->newestFirst()
            ->with('author')
            ->get();

        return Inertia::render('secrets/History', [
            'vault' => $vault->toClientArray($this->membershipFor($vault, $request)),
            'lockbox' => $secret->lockbox->toClientArray(),
            'secret' => $secret->toClientArray(),
            'versions' => $versions->map(fn (SecretVersion $version): array => $version->toClientArray()),
        ]);
    }

    /**
     * Erases the whole history of one secret, immediately and for good.
     *
     * The one action in this application that is destructive on purpose and
     * without a grace period, because a grace period would defeat it. The case
     * this exists for is a credential rotated *because it leaked*: keeping the
     * leaked value in a table for another thirty days, recoverable by anybody
     * who can reach the vault, is exactly the state the user is trying to get
     * out of.
     *
     * The rows go; the record that they went does not. `count` is structural —
     * how many, never what — so the log can say history was erased here without
     * becoming a place where the erased thing survives.
     */
    public function destroy(Secret $secret): RedirectResponse
    {
        DB::transaction(function () use ($secret): void {
            // The query builder, as everywhere else these rows are removed in
            // bulk: it returns how many went, which is the number the log needs.
            $count = DB::table('secret_versions')->where('secret_id', $secret->getKey())->delete();

            AuditLog::record(AuditAction::SecretHistoryPurged, $secret, ['count' => $count]);
        });

        return back();
    }
}
