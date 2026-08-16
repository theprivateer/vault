<?php

namespace App\Support;

use App\Models\Lockbox;
use App\Models\Secret;
use App\Models\SecretVersion;
use App\Models\User;
use App\Models\Vault;
use App\Models\VaultFile;
use App\Models\VaultMembership;
use App\Rules\Envelope;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Config;

/**
 * What the server can and cannot say about the state of its own key hierarchy.
 *
 * **Be precise about the "cannot", because it is most of the answer.** This
 * server holds no key. It cannot tell whether a wrapped Item Key actually opens
 * under the Vault Key it claims to be wrapped by, whether a payload decrypts, or
 * whether a member's sealed key is the one they think it is. Every one of those
 * questions is answered in a browser or not at all, and a "verification" that
 * implied otherwise would be worse than none — it would report health it never
 * measured.
 *
 * What it *can* check is structural, and every one of these is a real fault that
 * has a real consequence:
 *
 *  - A live membership on an old `key_epoch`. Their sealed key no longer opens
 *    anything written since the rotation, so they hold access that silently does
 *    not work.
 *  - A vault told to re-key that never did. A removed member's cached Vault Key
 *    still opens everything written since they left — which is the entire reason
 *    revocation sets the flag.
 *  - A vault with no live administrator. Nobody can rotate it, share it, or
 *    delete it, ever.
 *  - A row whose wrapped key is not a plausible envelope. It was written by
 *    something that was not this application, or it has been corrupted.
 *  - A live membership whose user has published no identity. Rotation seals the
 *    new Vault Key to each member's public key; there is nothing to seal to.
 *
 * Deliberately shared between `vault:verify-keys` and `vault:health` so the two
 * cannot drift apart about what a fault is.
 */
final class KeyAudit
{
    /**
     * Every structural fault in one vault, in the order somebody would fix them.
     *
     * @return list<string>
     */
    public static function faultsIn(Vault $vault): array
    {
        $faults = [];

        $memberships = $vault->memberships()->whereNull('revoked_at')->with('user.identity')->get();

        if ($memberships->isEmpty()) {
            $faults[] = 'no live members: nobody holds a key to this vault, and nobody ever can again';
        }

        if (! $memberships->contains(fn (VaultMembership $m): bool => $m->role->canAdminister())) {
            $faults[] = 'no live administrator: it cannot be shared, rotated or deleted by anyone';
        }

        foreach ($memberships as $membership) {
            if ($membership->key_epoch !== $vault->key_epoch) {
                $faults[] = "membership {$membership->uuid} is stranded on key epoch "
                    ."{$membership->key_epoch} while the vault is on {$vault->key_epoch}: their key "
                    .'no longer opens anything written since the rotation';
            }

            if ($membership->user->identity === null) {
                $faults[] = "membership {$membership->uuid} belongs to an account with no published "
                    .'keys, so the next rotation has nothing to seal their copy to';
            }

            if (! self::isPlausibleEnvelope($membership->wrapped_vault_key, sealed: true)) {
                $faults[] = "membership {$membership->uuid} holds a wrapped vault key that is not a "
                    .'readable envelope';
            }
        }

        if ($vault->rekey_required_at !== null) {
            $days = (int) $vault->rekey_required_at->diffInDays(now());

            $faults[] = "a re-key has been required for {$days} day".($days === 1 ? '' : 's')
                .': until it happens, a removed member’s cached key still opens everything '
                .'written since they left';
        }

        foreach (self::itemKeys($vault) as $label => $wrapped) {
            if (! self::isPlausibleEnvelope($wrapped)) {
                $faults[] = "{$label} holds a wrapped item key that is not a readable envelope";
            }
        }

        return $faults;
    }

    /**
     * Deployment-wide counts, for `vault:health`.
     *
     * @return array{vaults: int, vaultsNeedingRekey: int, vaultsDueForRotation: int, staleRekeyDays: int, usersBehindOnKdf: int, usersWithoutIdentity: int, legacyEnvelopes: int, immutableEnvelopes: int, totalEnvelopes: int}
     */
    public static function summary(): array
    {
        $envelopes = self::envelopeVersions();

        return [
            'vaults' => Vault::query()->count(),
            'vaultsNeedingRekey' => Vault::query()->whereNotNull('rekey_required_at')->count(),
            'vaultsDueForRotation' => Vault::query()
                ->get()
                ->filter(fn (Vault $vault): bool => $vault->isRotationDue())
                ->count(),
            'staleRekeyDays' => Config::integer('vault.rotation.stale_after_days'),
            'usersBehindOnKdf' => User::query()
                ->get()
                ->filter(fn (User $user): bool => KdfPolicy::isBehind($user))
                ->count(),
            'usersWithoutIdentity' => User::query()->whereDoesntHave('identity')->count(),
            'legacyEnvelopes' => $envelopes['legacy'],
            'immutableEnvelopes' => $envelopes['immutable'],
            'totalEnvelopes' => $envelopes['total'],
        ];
    }

    /**
     * How many stored envelopes are still on the old version.
     *
     * Reading byte zero of a ciphertext column is not a crack in SR2 — see
     * `Ciphertext::envelopeVersion`. It is the only way to know whether the
     * algorithm agility designed in Phase 1 has actually moved anything, and an
     * agility mechanism nobody can measure is a comment.
     *
     * **`legacy` and `immutable` are counted apart on purpose.** A number that
     * cannot reach zero is a number people stop reading: archived versions are
     * immutable by design — an archive that could be rewritten is a rollback
     * channel for a credential somebody rotated *because* it leaked — so they
     * stay on the old envelope until retention removes them. Only `legacy` is
     * work somebody can do, and `vault:reseal`'s page is where they do it.
     *
     * Payload columns only. A wrapped key is re-wrapped by a re-key rather than
     * by an edit, so counting those together would conflate two migrations that
     * happen for different reasons and at different times.
     *
     * @return array{legacy: int, immutable: int, total: int}
     */
    public static function envelopeVersions(): array
    {
        $legacy = 0;
        $immutable = 0;
        $total = 0;

        $sources = [
            [Vault::withTrashed()->lazy(), false],
            [Lockbox::withTrashed()->lazy(), false],
            [Secret::withTrashed()->lazy(), false],
            [VaultFile::withTrashed()->lazy(), false],
            [SecretVersion::query()->lazy(), true],
        ];

        foreach ($sources as [$rows, $rewritable]) {
            foreach ($rows as $row) {
                $version = $row->payload_ct->envelopeVersion();
                $total++;

                if ($version === null || $version >= Envelope::CURRENT_VERSION) {
                    continue;
                }

                $rewritable ? $immutable++ : $legacy++;
            }
        }

        return ['legacy' => $legacy, 'immutable' => $immutable, 'total' => $total];
    }

    /**
     * Every row in a vault holding a key wrapped under the Vault Key, labelled.
     *
     * The same set `VaultRekeyController::itemKeys()` covers, and it has to stay
     * the same set: a table that holds a wrapped key and is missing from either
     * is a table a rotation would strand. Trashed rows are included, because a
     * soft-deleted secret is restorable and its key is still a key.
     *
     * @return Collection<string, Ciphertext>
     */
    private static function itemKeys(Vault $vault): Collection
    {
        $lockboxes = Lockbox::withTrashed()->where('vault_id', $vault->getKey())->get(['id', 'uuid', 'wrapped_item_key']);
        $secrets = Secret::withTrashed()->whereIn('lockbox_id', $lockboxes->modelKeys())->get(['id', 'uuid', 'wrapped_item_key']);

        /** @var Collection<string, Ciphertext> $keys */
        $keys = new Collection;

        foreach ($lockboxes as $lockbox) {
            $keys->put("lockbox {$lockbox->uuid}", $lockbox->wrapped_item_key);
        }

        foreach ($secrets as $secret) {
            $keys->put("secret {$secret->uuid}", $secret->wrapped_item_key);
        }

        foreach (VaultFile::withTrashed()->whereIn('lockbox_id', $lockboxes->modelKeys())->get(['id', 'uuid', 'wrapped_item_key']) as $file) {
            $keys->put("file {$file->uuid}", $file->wrapped_item_key);
        }

        foreach (SecretVersion::query()->whereIn('secret_id', $secrets->modelKeys())->get(['id', 'uuid', 'wrapped_item_key']) as $version) {
            $keys->put("version {$version->uuid}", $version->wrapped_item_key);
        }

        return $keys;
    }

    /**
     * Shape and version only — the same two bytes `App\Rules\Envelope` checks on
     * the way in. This decrypts nothing and could not: there is no key here.
     */
    private static function isPlausibleEnvelope(Ciphertext $value, bool $sealed = false): bool
    {
        $bytes = $value->bytes();
        $prefix = $sealed ? Envelope::SEALED_PREFIX_BYTES : 0;

        if (strlen($bytes) < $prefix + Envelope::MIN_BYTES) {
            return false;
        }

        return in_array(ord($bytes[$prefix]), Envelope::SUPPORTED_VERSIONS, true)
            && in_array(ord($bytes[$prefix + 1]), Envelope::SUPPORTED_ALGORITHMS, true);
    }
}
