<?php

namespace App\Http\Controllers;

use App\Enums\AuditAction;
use App\Enums\VaultRole;
use App\Http\Requests\TransferOwnershipRequest;
use App\Models\User;
use App\Models\Vault;
use App\Models\VaultMembership;
use App\Support\AuditLog;
use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\ValidationException;

/**
 * Handing a vault over.
 *
 * **Nothing cryptographic happens here, and that is the design rather than an
 * omission.** The recipient must already be a member, which means the Vault Key
 * is already sealed to their public key on their own membership row. Transfer
 * moves an authorisation fact — who may share, revoke, rotate and delete — and
 * the ability to decrypt was settled when they were granted access.
 *
 * The corollary is the part the interface has to say out loud: the outgoing
 * owner keeps their key. They become an editor, they can still read everything,
 * and no server-side change alters that. Getting somebody out of a vault is
 * revocation plus a re-key, which is a different operation with a different
 * cost, and calling this one "transfer" must not be allowed to imply it.
 *
 * Why it exists at all: `vaults.owner_id` and the membership rows have to agree,
 * so the sharing path refuses to grant the owner role and this is the only way
 * the role moves. Without it, a vault with members could never be handed on, and
 * its owner could never leave — which is the same problem the deletion guard in
 * VaultController runs into from the other side.
 */
class VaultOwnershipController extends Controller
{
    /**
     * Moves ownership to an existing member, and demotes the current owner.
     *
     * Inside one transaction with the vault row locked, for the reason the
     * re-key path locks it: two administrators acting at once would otherwise
     * both read the vault as theirs and both write, leaving two membership rows
     * claiming the owner role and `owner_id` naming whichever committed last.
     * There is exactly one owner, and that has to survive concurrency.
     */
    public function update(TransferOwnershipRequest $request, Vault $vault): RedirectResponse
    {
        $current = $this->currentUser($request);
        $recipient = User::query()->where('uuid', $request->string('user_uuid')->toString())->firstOrFail();

        DB::transaction(function () use ($vault, $current, $recipient): void {
            $locked = Vault::query()
                ->whereKey($vault->getKey())
                ->lockForUpdate()
                ->firstOrFail();

            $outgoing = $this->assertStillOwner($locked, $current);
            $incoming = $this->assertEligible($locked, $recipient, $current);

            $previousRole = $incoming->role;

            $incoming->forceFill(['role' => VaultRole::Owner])->save();

            /*
             | Demoted rather than revoked. Revoking would strip the row that
             | holds this person's sealed Vault Key, and their access has to
             | outlive the transfer for the obvious reason — they were using this
             | vault a moment ago. Leaving is a separate decision, and now a
             | possible one: an editor can be revoked, whereas an administrator
             | cannot, which is what made the old owner immovable.
             */
            $outgoing->forceFill(['role' => VaultRole::Editor])->save();

            $locked->forceFill(['owner_id' => $recipient->getKey()])->save();

            AuditLog::record(AuditAction::VaultOwnershipTransferred, $incoming, [
                'previous_role' => $previousRole->value,
                'role' => VaultRole::Owner->value,
            ], $current);
        });

        return to_route('vaults.show', $vault);
    }

    /**
     * The actor's own membership, re-read under the lock.
     *
     * The policy checked this before the request was resolved, on a row read
     * outside the transaction. A transfer that committed in between would leave
     * this one demoting somebody who is no longer the owner.
     */
    private function assertStillOwner(Vault $vault, User $user): VaultMembership
    {
        $membership = $vault->membershipFor($user);

        if ($membership === null || ! $membership->role->canAdminister()) {
            throw ValidationException::withMessages([
                'user_uuid' => 'This vault is no longer yours to hand over. Reload the page to see '
                    .'who owns it now.',
            ]);
        }

        return $membership;
    }

    /**
     * The recipient's membership, or a refusal that says what to do instead.
     *
     * Three conditions, and each of them describes a way to create an owner who
     * cannot own anything:
     *
     * - **A live membership**, because ownership without a sealed Vault Key is a
     *   title over a vault you cannot open. Somebody who is not a member has to
     *   be shared with first, through the flow that shows them a fingerprint.
     * - **The current key epoch**, because a membership stranded on an old one
     *   holds a key that no longer unwraps anything, and handing them the vault
     *   would leave nobody able to rotate it back.
     * - **An accepted grant**, because accepting is the recipient confirming
     *   they compared your fingerprint out of band. Administration is the last
     *   thing to hand to an account that has not yet said it trusts you — and it
     *   is also the only evidence available here that their client engaged with
     *   the grant at all.
     */
    private function assertEligible(Vault $vault, User $recipient, User $current): VaultMembership
    {
        if ($recipient->is($current)) {
            throw ValidationException::withMessages([
                'user_uuid' => 'You already own this vault.',
            ]);
        }

        $membership = $vault->membershipFor($recipient);

        if ($membership === null) {
            /*
             | Deliberately says nothing about whether the account exists in this
             | vault under a revoked row, or at all. The actor is an
             | administrator of this vault and could look either up, so there is
             | no oracle to protect here — the wording is chosen because it names
             | the fix rather than the fault.
             */
            throw ValidationException::withMessages([
                'user_uuid' => 'Ownership can only go to somebody who already has access to this '
                    .'vault. Share it with them first — they need a copy of the key before they '
                    .'can be its owner.',
            ]);
        }

        if (! $membership->isCurrentEpoch()) {
            throw ValidationException::withMessages([
                'user_uuid' => 'Their key is from before the last rotation, so it no longer opens '
                    .'this vault. Re-key the vault before handing it over.',
            ]);
        }

        if ($membership->accepted_at === null) {
            throw ValidationException::withMessages([
                'user_uuid' => 'They have not confirmed your fingerprint yet. Ask them to open the '
                    .'vault and acknowledge the share before you hand it to them.',
            ]);
        }

        return $membership;
    }
}
