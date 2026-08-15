<?php

namespace App\Http\Controllers;

use App\Enums\VaultRole;
use App\Http\Requests\StoreMembershipRequest;
use App\Models\User;
use App\Models\Vault;
use App\Models\VaultMembership;
use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\ValidationException;

/**
 * Sharing a vault: grant, accept, revoke.
 *
 * The server's part in this is smaller than it looks. It stores a sealed key it
 * cannot open and a signature it cannot meaningfully check, and it enforces one
 * thing that is genuinely its own: access. Everything cryptographic happens at
 * the two ends.
 */
class VaultMembershipController extends Controller
{
    /**
     * Grants access, storing the Vault Key sealed to the recipient.
     *
     * **What the server verifies about the grant, and why it is not security.**
     * The signed payload is compared against the row being written — same vault,
     * same recipient, same role, same epoch. A server that wanted to lie would
     * simply skip this check, so it defends against nothing. It is here to catch
     * a client that built the grant wrong, at the moment the mistake is made
     * rather than weeks later when a recipient cannot accept and nobody can say
     * why. The check that matters runs in the recipient's browser, against a
     * pinned public key.
     *
     * Re-granting to someone previously revoked updates their existing row: the
     * unique constraint on (vault, user) makes that the only option, and it is
     * the right one, provided `accepted_at` is cleared. It is cleared. A
     * returning member re-verifies, because the reason they were removed may be
     * the reason their keys should not be trusted.
     */
    public function store(StoreMembershipRequest $request, Vault $vault): RedirectResponse
    {
        $recipient = User::query()
            ->where('uuid', $request->string('user_uuid')->toString())
            ->firstOrFail();

        if ($recipient->identity === null) {
            throw ValidationException::withMessages([
                'user_uuid' => 'That account has not published any public keys, so a vault key '
                    .'cannot be sealed to it.',
            ]);
        }

        $role = VaultRole::from($request->string('role')->toString());
        $payload = $request->string('grant_payload')->toString();

        $this->assertGrantDescribes($payload, $vault, $recipient, $role);

        // Through the relation, so `vault_id` is set by the relationship rather
        // than being mass-assignable on the model.
        $vault->memberships()->updateOrCreate(
            ['user_id' => $recipient->getKey()],
            [
                'uuid' => $request->string('membership_uuid')->toString(),
                'role' => $role,
                'wrapped_vault_key' => $request->string('wrapped_vault_key')->toString(),
                'key_epoch' => $vault->key_epoch,
                'granted_by' => $this->currentUser($request)->getKey(),
                'grant_signature' => $request->string('grant_signature')->toString(),

                /*
                 | Stored as the exact string that was signed, never decoded and
                 | re-encoded. A signature verifies over bytes, and a round trip
                 | through json_decode/json_encode is free to change them — the
                 | escaping of `/`, of non-ASCII, of anything a future field
                 | introduces. Every one of those would turn a valid grant into
                 | one no recipient could verify, and the failure would look like
                 | an attack rather than a bug.
                 */
                'grant_payload' => $payload,

                'accepted_at' => null,
                'revoked_at' => null,
            ],
        );

        return back();
    }

    /**
     * The recipient confirming they verified the granter's fingerprint.
     *
     * Recording it server-side is bookkeeping — it drives the "needs checking"
     * badge and, later, an audit event. It confers nothing: a membership is
     * usable from the moment it is granted, because usability is a matter of
     * holding the sealed key, which no server flag affects. The security
     * decision lives in the recipient's pin store.
     */
    public function accept(VaultMembership $membership): RedirectResponse
    {
        $membership->forceFill(['accepted_at' => now()])->save();

        return back();
    }

    /**
     * Revokes a membership and marks the vault as needing a new key.
     *
     * Two things happen in one transaction, and they are not the same kind of
     * thing. Cutting API access is instant and enforceable, and it is done here.
     * Rotating the key is neither — it needs an owner's browser, since only a
     * member can unwrap the current Vault Key — so it is recorded as a
     * requirement and prompted for on their next unlock.
     *
     * Between those two moments the removed member can still read anything they
     * cached, and rotation will not change that either. The UI says so.
     */
    public function revoke(VaultMembership $membership): RedirectResponse
    {
        DB::transaction(function () use ($membership): void {
            $membership->forceFill(['revoked_at' => now()])->save();

            $membership->vault->forceFill(['rekey_required_at' => now()])->save();
        });

        return back();
    }

    /**
     * Compares the signed grant with the row it is meant to authorise.
     *
     * See the note on `store`: this catches client mistakes, not attacks.
     */
    private function assertGrantDescribes(
        string $payload,
        Vault $vault,
        User $recipient,
        VaultRole $role,
    ): void {
        $grant = json_decode($payload, true);

        if (! is_array($grant)) {
            throw ValidationException::withMessages(['grant_payload' => 'The grant is not readable.']);
        }

        $expected = [
            'vaultUuid' => $vault->uuid,
            'recipientUuid' => $recipient->uuid,
            'role' => $role->value,
            'keyEpoch' => $vault->key_epoch,
        ];

        foreach ($expected as $field => $value) {
            if (($grant[$field] ?? null) !== $value) {
                throw ValidationException::withMessages([
                    'grant_payload' => "The signed grant disagrees with this request about {$field}. "
                        .'Nothing was saved — the recipient would not have been able to accept it.',
                ]);
            }
        }
    }
}
