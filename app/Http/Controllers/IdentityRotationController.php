<?php

namespace App\Http\Controllers;

use App\Enums\AuditAction;
use App\Http\Requests\RotateIdentityRequest;
use App\Models\User;
use App\Models\UserIdentity;
use App\Models\VaultMembership;
use App\Support\AuditLog;
use App\Support\Ciphertext;
use App\Support\KdfPolicy;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\ValidationException;
use Inertia\Inertia;
use Inertia\Response;

/**
 * Replacing your own identity keys.
 *
 * **Self-service, which is the surprising part.** Every Vault Key you hold is
 * sealed to your X25519 public key, and you still have the matching private key
 * — so your own browser can open each one and re-seal it to a fresh pair. No
 * vault owner is involved, no Vault Key changes, and no payload is re-encrypted.
 * The server receives a new public bundle and a complete set of re-sealed
 * membership keys, none of which it can read.
 *
 * **It is all or nothing, for the same reason a vault re-key is.** The old
 * private key is gone the moment this lands. A membership missing from the
 * submission is a sealed Vault Key with no surviving key to open it: the vault
 * becomes permanently unreadable *for this user*, silently, with the request
 * having reported success. So the set is checked against the database and an
 * incomplete one is refused — the same defence, and the same failure it defends
 * against, as `VaultRekeyController`.
 *
 * **What this does not do.** Rotating your keys does not rotate any Vault Key,
 * so it does not remove anybody else's access to anything and does not help if
 * the *vault* key leaked. And it invalidates every peer's pin of you, by design:
 * they see a changed fingerprint, which is indistinguishable from a server
 * substituting a key. The certificate signed by your retiring key is what lets
 * them tell the difference — see docs/03 § Identity key rotation — and it is
 * evidence, never an automatic accept, because whoever holds a stolen key can
 * sign one just as well.
 */
class IdentityRotationController extends Controller
{
    public function create(Request $request): Response
    {
        $user = $this->currentUser($request);

        return Inertia::render('account/RotateIdentity', [
            'identity' => $user->identity?->toOwnerBundle(),

            /*
             | The account's own key health, shown where the person who can act
             | on it is standing. There is no operator dashboard over everybody's
             | accounts — D11 has no organisation layer, and inventing an
             | administrator role to host one would grant a view the product
             | otherwise refuses. `vault:health` is the deployment-wide answer,
             | for somebody who already has shell access.
             */
            'kdf' => [
                'current' => $user->kdf_params,
                'target' => KdfPolicy::target(),
                'behind' => KdfPolicy::isBehind($user),
            ],

            'rotatedAt' => $user->identity?->rotated_at?->toIso8601String(),

            /*
             | Every live membership, with the sealed key the browser has to
             | open and re-seal. Sent whole rather than paginated: a partial list
             | would produce a partial submission, which the server refuses —
             | correctly, and after the user has waited.
             */
            'memberships' => $this->liveMemberships($user)
                ->map(fn (VaultMembership $membership): array => [
                    'uuid' => $membership->uuid,
                    'wrappedVaultKey' => $membership->wrapped_vault_key->base64,
                    'vaultUuid' => $membership->vault->uuid,
                    'role' => $membership->role->value,
                ])
                ->values(),
        ]);
    }

    /**
     * Applies the rotation, or nothing at all.
     *
     * One transaction with the identity row locked, so two tabs cannot both
     * rotate from the same starting keys and leave the archive describing a
     * chain that never happened.
     */
    public function store(RotateIdentityRequest $request): RedirectResponse
    {
        $user = $this->currentUser($request);

        DB::transaction(function () use ($request, $user): void {
            $identity = UserIdentity::query()
                ->where('user_id', $user->getKey())
                ->lockForUpdate()
                ->first();

            if ($identity === null) {
                throw ValidationException::withMessages([
                    'fingerprint' => 'This account has no published keys to replace.',
                ]);
            }

            $submitted = $this->keyedByUuid($request->array('memberships'));
            $live = $this->liveMemberships($user);

            $this->assertComplete($live, array_keys($submitted));
            $this->assertCertificateDescribes($request, $user, $identity);

            /*
             | Archived before the row is overwritten, and with the certificate
             | that retires it. Public halves only: the private keys are what a
             | rotation exists to discard, and keeping a copy would make the
             | operation a rename.
             */
            $user->identityArchive()->create([
                'x25519_public_key' => $identity->x25519_public_key->base64,
                'ed25519_public_key' => $identity->ed25519_public_key->base64,
                'self_signature' => $identity->self_signature->base64,
                'fingerprint' => $identity->fingerprint->base64,
                'rotation_payload' => $request->string('rotation_payload')->toString(),
                'rotation_signature' => $request->string('rotation_signature')->toString(),
                'rotated_at' => now(),
            ]);

            $identity->forceFill([
                'x25519_public_key' => $request->string('x25519_public_key')->toString(),
                'ed25519_public_key' => $request->string('ed25519_public_key')->toString(),
                'x25519_private_key_ct' => $request->string('x25519_private_key_ct')->toString(),
                'ed25519_private_key_ct' => $request->string('ed25519_private_key_ct')->toString(),
                'self_signature' => $request->string('self_signature')->toString(),
                'fingerprint' => $request->string('fingerprint')->toString(),
                'rotated_at' => now(),
            ])->save();

            foreach ($live as $membership) {
                $membership->forceFill([
                    'wrapped_vault_key' => Ciphertext::fromBase64($submitted[$membership->uuid])->base64,

                    /*
                     | `accepted_at` is deliberately untouched. Acceptance is the
                     | recipient's record that they checked the *granter's*
                     | fingerprint, and rotating their own keys says nothing
                     | about that check. Clearing it would ask everybody to
                     | re-verify people they have not stopped trusting.
                     */
                ])->save();
            }

            /*
             | The count is what makes an incomplete rotation visible after the
             | fact — the same reason a re-key records `rewrapped`. The
             | transaction makes a partial write impossible; the log is read by
             | somebody who was not here and cannot take that on faith.
             */
            AuditLog::record(AuditAction::IdentityRotated, $user, ['count' => $live->count()], $user);
        });

        return back();
    }

    /**
     * Every membership whose sealed key must move to the new identity.
     *
     * Revoked rows are excluded. Their sealed key opens nothing the user is
     * entitled to and carrying it across would re-seal access that was
     * deliberately withdrawn — the row survives as a record, not as a key.
     *
     * @return Collection<int, VaultMembership>
     */
    private function liveMemberships(User $user): Collection
    {
        return $user->vaultMemberships()
            ->whereNull('revoked_at')
            ->with('vault')
            ->get();
    }

    /**
     * @param  array<array-key, mixed>  $rows
     * @return array<string, string>
     */
    private function keyedByUuid(array $rows): array
    {
        $keyed = [];

        foreach ($rows as $row) {
            if (is_array($row) && is_string($row['uuid'] ?? null) && is_string($row['wrapped_vault_key'] ?? null)) {
                $keyed[$row['uuid']] = $row['wrapped_vault_key'];
            }
        }

        return $keyed;
    }

    /**
     * Refuses anything but an exactly complete set.
     *
     * Nothing missing, and nothing extra. A submission naming a membership that
     * is not this user's live set is a client working from a stale picture, and
     * the entries it *did* send are then unlikely to be the whole set either —
     * the same reasoning as the vault re-key, and the same refusal.
     *
     * @param  Collection<int, VaultMembership>  $live
     * @param  list<string>  $submitted
     */
    private function assertComplete(Collection $live, array $submitted): void
    {
        $expected = $live->map(fn (VaultMembership $membership): string => $membership->uuid)->all();

        $missing = array_diff($expected, $submitted);
        $extra = array_diff($submitted, $expected);

        if ($missing === [] && $extra === []) {
            return;
        }

        throw ValidationException::withMessages([
            'memberships' => 'This rotation covers '.count($submitted).' of your '.count($expected)
                .' vault keys. It has to be all of them at once — the old key is discarded when this '
                .'lands, so anything left behind could never be opened again. Nothing was changed; '
                .'reload and try again.',
        ]);
    }

    /**
     * Compares the certificate with the change it claims to describe.
     *
     * **This is not security and is not pretending to be.** A malicious server
     * would simply skip it, and the signature is deliberately *not* verified
     * here — the server publishes the public key it would check against, so it
     * would only ever be checking its own work (see `App\Rules\Signature`). The
     * check that counts happens in a peer's browser against a pinned key.
     *
     * It is here to catch a client that built the certificate wrong, at the
     * moment the mistake is made. Without it the failure is invisible until some
     * peer, weeks later, is shown a hard stop for a rotation that was genuine —
     * and nobody can say why.
     */
    private function assertCertificateDescribes(
        RotateIdentityRequest $request,
        User $user,
        UserIdentity $identity,
    ): void {
        $statement = json_decode($request->string('rotation_payload')->toString(), true);

        if (! is_array($statement)) {
            throw ValidationException::withMessages([
                'rotation_payload' => 'The rotation notice is not readable.',
            ]);
        }

        $expected = [
            'userUuid' => $user->uuid,
            'previousFingerprint' => bin2hex($identity->fingerprint->bytes()),
            'fingerprint' => bin2hex(Ciphertext::fromBase64(
                $request->string('fingerprint')->toString()
            )->bytes()),
        ];

        foreach ($expected as $field => $value) {
            if (($statement[$field] ?? null) !== $value) {
                throw ValidationException::withMessages([
                    'rotation_payload' => "The rotation notice disagrees with this request about {$field}. "
                        .'Nothing was changed — nobody would have been able to verify it.',
                ]);
            }
        }
    }
}
