<?php

namespace App\Http\Controllers;

use App\Enums\VaultRole;
use App\Http\Requests\StoreVaultRequest;
use App\Http\Requests\UpdateItemRequest;
use App\Models\Lockbox;
use App\Models\Vault;
use App\Models\VaultMembership;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Inertia\Inertia;
use Inertia\Response;

/**
 * Vaults.
 *
 * Every method here moves opaque blobs. The interesting property is what is
 * missing: there is no code path that could render a vault's name, because
 * nothing on this server has ever seen one.
 */
class VaultController extends Controller
{
    /**
     * The list is built from memberships rather than from vaults, because a
     * membership *is* the access grant. There is no query here that could
     * return a vault the user has no row for.
     */
    public function index(Request $request): Response
    {
        $vaults = $this->currentUser($request)
            ->vaultMemberships()
            ->whereNull('revoked_at')
            ->with('vault')
            ->get()
            // A vault in its deletion grace period is still loaded — the
            // relation includes trashed rows on purpose — so it is dropped here.
            ->reject(fn (VaultMembership $membership): bool => $membership->vault->trashed())
            ->map(fn (VaultMembership $membership): array => $membership->vault->toClientArray($membership))
            ->values();

        return Inertia::render('vaults/Index', ['vaults' => $vaults]);
    }

    public function show(Request $request, Vault $vault): Response
    {

        $lockboxes = $vault->lockboxes()
            ->withCount('secrets')
            ->orderBy('sort_order')
            ->orderBy('uuid')
            ->get()
            ->map(fn (Lockbox $lockbox): array => $lockbox->toClientArray());

        return Inertia::render('vaults/Show', [
            'vault' => $vault->toClientArray($this->membershipFor($vault, $request)),
            'lockboxes' => $lockboxes,
        ]);
    }

    /**
     * Creates the vault and the creator's own membership atomically.
     *
     * A vault without a membership row would be unreachable by anyone,
     * including its owner: the Vault Key exists only as the sealed copy on that
     * row. There is no second copy anywhere, and no way to make one.
     */
    public function store(StoreVaultRequest $request): RedirectResponse
    {
        $user = $this->currentUser($request);

        $vault = DB::transaction(function () use ($request, $user): Vault {
            $vault = $user->vaults()->create([
                'uuid' => $request->string('uuid')->toString(),
                'payload_ct' => $request->string('payload_ct')->toString(),
                'wrapped_item_key' => $request->string('wrapped_item_key')->toString(),
                'payload_version' => $request->integer('payload_version'),
                // Set here rather than left to the column default, so the
                // membership below can be written in the same transaction
                // without reading the row back.
                'key_epoch' => Vault::INITIAL_KEY_EPOCH,
            ]);

            $vault->memberships()->create([
                'uuid' => $request->string('membership_uuid')->toString(),
                'user_id' => $user->getKey(),
                'role' => VaultRole::Owner,
                'wrapped_vault_key' => $request->string('wrapped_vault_key')->toString(),
                'key_epoch' => $vault->key_epoch,
                'granted_by' => $user->getKey(),
            ]);

            return $vault;
        });

        return to_route('vaults.show', $vault);
    }

    public function update(UpdateItemRequest $request, Vault $vault): RedirectResponse
    {

        $vault->update([
            'payload_ct' => $request->string('payload_ct')->toString(),
            'wrapped_item_key' => $request->string('wrapped_item_key')->toString(),
            'payload_version' => $request->integer('payload_version'),
        ]);

        return back();
    }

    /**
     * Soft delete, per the 30-day grace period in docs/04-data-model.md. The job
     * that hard-deletes the rows and their object-storage blobs arrives with
     * files in Phase 6.
     */
    public function destroy(Vault $vault): RedirectResponse
    {

        $vault->delete();

        return to_route('vaults.index');
    }
}
