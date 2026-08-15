<?php

namespace App\Http\Controllers;

use App\Enums\AuditAction;
use App\Http\Requests\RekeyVaultRequest;
use App\Models\Lockbox;
use App\Models\Secret;
use App\Models\SecretVersion;
use App\Models\Vault;
use App\Models\VaultFile;
use App\Models\VaultMembership;
use App\Support\AuditLog;
use App\Support\Ciphertext;
use App\Support\ItemKey;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Collection as Support;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\ValidationException;
use Inertia\Inertia;
use Inertia\Response;

/**
 * Rotating a vault's key, atomically.
 *
 * Revocation without rotation is theatre: a removed member's browser may have
 * cached the Vault Key, and no server-side flag reaches into it. So revocation
 * marks the vault as needing a new key, and this is where the new key arrives.
 *
 * **Why it is one request.** The client generates a new Vault Key, unwraps every
 * item key under the old one, re-wraps every one under the new one, seals the
 * new key to each remaining member, and submits the lot. The server accepts it
 * only at exactly `key_epoch + 1` and only with a complete set. A partial
 * re-key is rejected rather than half-applied.
 *
 * That is the explicit correction of the 2017 `vault:key` artisan command, which
 * re-encrypted item by item and left vaults in a mixed state whenever it was
 * interrupted — with no way to tell which items were on which key.
 *
 * **What rotation does not do.** Payload ciphertexts are untouched, which is why
 * this is milliseconds rather than minutes. And it cannot retract a read that
 * already happened. The interface says so; see resources/js/pages/vaults/Rekey.vue.
 */
class VaultRekeyController extends Controller
{
    /**
     * Everything the owner's browser needs to perform the rotation.
     *
     * Trashed lockboxes and secrets are included deliberately. During the
     * deletion grace period they are still rows holding item keys wrapped under
     * the *old* Vault Key, and a rotation that skipped them would quietly make
     * them unrecoverable — turning "deleted, restorable for 30 days" into
     * "deleted" without anyone choosing that.
     */
    public function create(Request $request, Vault $vault): Response
    {
        $memberships = $this->liveMemberships($vault);

        return Inertia::render('vaults/Rekey', [
            'vault' => $vault->toClientArray($this->membershipFor($vault, $request)),
            'items' => $this->itemKeys($vault)
                ->map(fn (ItemKey $item): array => [
                    'uuid' => $item->uuid,
                    'wrappedItemKey' => $item->wrappedItemKey,
                ])
                ->values(),
            'members' => $memberships
                ->map(fn (VaultMembership $membership): array => [
                    ...$membership->toClientArray(),
                    // The public key the new Vault Key gets sealed to, and the
                    // fingerprint the owner must confirm before it does.
                    'identity' => $membership->user->identity?->toPublicBundle(),
                ])
                ->values(),
        ]);
    }

    /**
     * Applies the rotation, or nothing at all.
     *
     * Everything below runs inside one transaction with the vault row locked.
     * The epoch check has to happen after the lock rather than before it: two
     * owners rotating at once would otherwise both read `key_epoch` as 3, both
     * find it acceptable, and the second would overwrite the first — leaving
     * members holding keys sealed under a Vault Key that no longer wraps
     * anything.
     */
    public function store(RekeyVaultRequest $request, Vault $vault): RedirectResponse
    {
        DB::transaction(function () use ($request, $vault): void {
            $locked = Vault::query()
                ->whereKey($vault->getKey())
                ->lockForUpdate()
                ->firstOrFail();

            $this->assertNextEpoch($request, $locked);

            $items = $this->keyedByUuid($request->array('items'), 'wrapped_item_key');
            $memberships = $this->keyedByUuid($request->array('memberships'), 'wrapped_vault_key');

            $expectedItems = $this->itemKeys($locked);
            $liveMemberships = $this->liveMemberships($locked);

            $this->assertComplete(
                $expectedItems->map(fn (ItemKey $item): string => $item->uuid)->all(),
                array_keys($items),
                'items',
                'item keys',
            );

            $this->assertComplete(
                $liveMemberships->map(fn (VaultMembership $member): string => $member->uuid)->all(),
                array_keys($memberships),
                'memberships',
                'members',
            );

            $this->rewrapItems($expectedItems, $items);

            foreach ($liveMemberships as $membership) {
                $membership->forceFill([
                    'wrapped_vault_key' => Ciphertext::fromBase64($memberships[$membership->uuid])->base64,
                    'key_epoch' => $request->integer('key_epoch'),
                ])->save();
            }

            $locked->forceFill([
                'wrapped_item_key' => Ciphertext::fromBase64(
                    $request->string('vault_wrapped_item_key')->toString()
                )->base64,
                'key_epoch' => $request->integer('key_epoch'),
                'rekey_required_at' => null,
            ])->save();

            /*
             | The count is what makes a partial re-key visible after the fact.
             | The request is all-or-nothing and this transaction enforces that,
             | but the log is read by someone who was not here at the time, and
             | "rotated the key" without a number leaves them unable to tell a
             | complete rotation from one that covered two items.
             */
            AuditLog::record(AuditAction::VaultRekeyed, $locked, [
                'key_epoch' => $request->integer('key_epoch'),
                'rewrapped' => count($items) + $liveMemberships->count(),
            ]);
        });

        return to_route('vaults.show', $vault);
    }

    /**
     * Every item in the vault that holds a key wrapped under the Vault Key.
     *
     * The vault's own payload key is not here — it is a column on the vault row
     * and is handled separately, so that "the item set is complete" stays a
     * statement about lockboxes and secrets and does not quietly depend on
     * remembering one extra thing.
     *
     * **Files and archived versions are in this set** (Phases 6 and 8). Both
     * hold Item Keys wrapped under the Vault Key exactly as a live secret does,
     * and both are easy to forget because neither appears on the page the owner
     * is looking at when they rotate. Leaving either out would produce a
     * rotation that reported success and quietly made every attachment and
     * every previous password in the vault unopenable — the same failure as
     * skipping trashed rows, arriving by a different route.
     *
     * @return Support<int, ItemKey>
     */
    private function itemKeys(Vault $vault): Support
    {
        $lockboxes = Lockbox::withTrashed()
            ->where('vault_id', $vault->getKey())
            ->get(['id', 'uuid', 'wrapped_item_key']);

        $secrets = Secret::withTrashed()
            ->whereIn('lockbox_id', $lockboxes->modelKeys())
            ->get(['id', 'uuid', 'wrapped_item_key']);

        $files = VaultFile::withTrashed()
            ->whereIn('lockbox_id', $lockboxes->modelKeys())
            ->get(['id', 'uuid', 'wrapped_item_key']);

        $versions = SecretVersion::query()
            ->whereIn('secret_id', $secrets->modelKeys())
            ->get(['id', 'uuid', 'wrapped_item_key']);

        return $lockboxes
            ->map(fn (Lockbox $lockbox): ItemKey => new ItemKey(
                $lockbox->uuid,
                $lockbox->wrapped_item_key->base64,
                'lockboxes',
                $lockbox->id,
            ))
            ->concat($secrets->map(fn (Secret $secret): ItemKey => new ItemKey(
                $secret->uuid,
                $secret->wrapped_item_key->base64,
                'secrets',
                $secret->id,
            )))
            ->concat($files->map(fn (VaultFile $file): ItemKey => new ItemKey(
                $file->uuid,
                $file->wrapped_item_key->base64,
                'files',
                $file->id,
            )))
            ->concat($versions->map(fn (SecretVersion $version): ItemKey => new ItemKey(
                $version->uuid,
                $version->wrapped_item_key->base64,
                'secret_versions',
                $version->id,
            )))
            ->values();
    }

    /**
     * @return Collection<int, VaultMembership>
     */
    private function liveMemberships(Vault $vault): Collection
    {
        return $vault->memberships()
            ->whereNull('revoked_at')
            ->with('user.identity', 'granter.identity')
            ->get();
    }

    /**
     * @param  Support<int, ItemKey>  $expected
     * @param  array<string, string>  $submitted
     */
    private function rewrapItems(Support $expected, array $submitted): void
    {
        foreach ($expected as $item) {
            DB::table($item->table)
                ->where('id', $item->id)
                ->update([
                    // Canonicalised by hand: a query-builder update writes
                    // columns without running the model's casts, and the
                    // Ciphertext cast is where base64 is normalised and capped.
                    'wrapped_item_key' => Ciphertext::fromBase64($submitted[$item->uuid])->base64,
                    'updated_at' => now(),
                ]);
        }
    }

    private function assertNextEpoch(RekeyVaultRequest $request, Vault $vault): void
    {
        if ($request->integer('key_epoch') !== $vault->key_epoch + 1) {
            throw ValidationException::withMessages([
                'key_epoch' => 'This vault has already been re-keyed since you started. '
                    .'Reload and try again — nothing has been changed.',
            ]);
        }
    }

    /**
     * Refuses anything but an exact match: nothing missing, nothing extra.
     *
     * "Nothing extra" matters as much as "nothing missing". A submission naming
     * an item that is not in the vault is a client working from a stale picture,
     * and the items it *did* send are then unlikely to be the whole set either.
     *
     * @param  array<int, string>  $expected
     * @param  array<int, string>  $submitted
     */
    private function assertComplete(array $expected, array $submitted, string $field, string $noun): void
    {
        $missing = array_diff($expected, $submitted);
        $extra = array_diff($submitted, $expected);

        if ($missing === [] && $extra === []) {
            return;
        }

        throw ValidationException::withMessages([
            $field => sprintf(
                'The re-key is incomplete: %d of %d %s were sent, and %d were not recognised. '
                    .'Nothing has been changed — the vault is still on its previous key.',
                count($submitted) - count($extra),
                count($expected),
                $noun,
                count($extra),
            ),
        ]);
    }

    /**
     * @param  array<array-key, mixed>  $rows
     * @return array<string, string>
     */
    private function keyedByUuid(array $rows, string $valueKey): array
    {
        $keyed = [];

        foreach ($rows as $row) {
            if (is_array($row) && is_string($row['uuid'] ?? null) && is_string($row[$valueKey] ?? null)) {
                $keyed[$row['uuid']] = $row[$valueKey];
            }
        }

        return $keyed;
    }
}
