<?php

namespace App\Http\Controllers;

use App\Enums\AuditAction;
use App\Models\Lockbox;
use App\Models\Secret;
use App\Models\VaultFile;
use App\Models\VaultMembership;
use App\Support\AuditLog;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Inertia\Inertia;
use Inertia\Response;

/**
 * Handing the whole account back (Phase 12, task 3).
 *
 * This endpoint is the largest read in the application by a wide margin, and it
 * is worth being clear about what that does and does not mean. It hands over
 * every ciphertext the caller already holds a key to — nothing more than the
 * vault pages would serve one at a time, gathered into a single response so the
 * browser can decrypt it in one pass. There is no new authority here and no new
 * leakage; there is a new *shape*, which is why it is audited as its own action
 * rather than as a run of ordinary reads.
 *
 * **Built from memberships, not from vaults.** Same rule as
 * VaultController::index: the query starts at the rows that grant access, so
 * there is no path here that could return a vault the caller has no membership
 * for. A `whereIn` over vault identifiers would have been shorter and would
 * have put the authorisation decision in a list rather than in a join.
 */
class AccountExportController extends Controller
{
    public function create(): Response
    {
        return Inertia::render('account/Export');
    }

    /**
     * Every vault, lockbox, secret and file this user can decrypt.
     *
     * Trashed rows are excluded. A soft-deleted secret is inside its 30-day
     * grace period and is still restorable, but an export is a snapshot of what
     * the account holds rather than of what it could get back — and an archive
     * that quietly reintroduced deleted credentials would be a surprise in the
     * wrong direction. The grace period is a property of this server, not
     * something a file on a USB stick can honour.
     */
    public function data(Request $request): JsonResponse
    {
        $user = $this->currentUser($request);

        $memberships = $user->vaultMemberships()
            ->whereNull('revoked_at')
            ->with('vault')
            ->get()
            ->reject(fn (VaultMembership $membership): bool => $membership->vault->trashed());

        $bundle = $memberships->map(function (VaultMembership $membership): array {
            $vault = $membership->vault;

            $lockboxes = $vault->lockboxes()->withCount('secrets')->orderBy('sort_order')->orderBy('uuid')->get();

            return [
                'vault' => $vault->toClientArray($membership),
                'lockboxes' => $lockboxes->map(fn (Lockbox $lockbox): array => $lockbox->toClientArray()),
                'secrets' => Secret::query()
                    ->whereIn('lockbox_id', $lockboxes->modelKeys())
                    ->with('lockbox', 'linkedLockbox')
                    ->orderBy('sort_order')
                    ->orderBy('uuid')
                    ->get()
                    ->map(fn (Secret $secret): array => $secret->toClientArray()),
                'files' => VaultFile::query()
                    ->whereIn('lockbox_id', $lockboxes->modelKeys())
                    ->with('lockbox')
                    ->orderBy('sort_order')
                    ->orderBy('uuid')
                    ->get()
                    ->map(fn (VaultFile $file): array => $file->toClientArray()),
            ];
        })->values();

        /*
         | Recorded before the response is built, so an export that fails
         | halfway through still leaves the entry. The alternative — log it once
         | the bytes are out — would mean the one read worth noticing is the one
         | read that can be made not to appear, by cutting the connection.
         */
        AuditLog::record(AuditAction::AccountExported, null, [
            'vault_count' => $bundle->count(),
            'secret_count' => $bundle->sum(fn (array $entry): int => count($entry['secrets'])),
            'file_count' => $bundle->sum(fn (array $entry): int => count($entry['files'])),
        ], $user);

        return response()->json([
            'handle' => $user->handle,
            'vaults' => $bundle,
        ]);
    }
}
