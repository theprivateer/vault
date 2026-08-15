<?php

namespace App\Policies;

use App\Models\User;
use App\Models\VaultMembership;
use Illuminate\Auth\Access\Response;

/**
 * Who may act on a membership row.
 *
 * The same two rules as every other policy here — access is a live membership,
 * and a denial is 404 rather than 403 — plus one that is specific to sharing:
 * **accepting and revoking are different people's business.** Only the recipient
 * can accept a grant, because accepting means "I checked the granter's
 * fingerprint", which nobody else is in a position to have done. Only an
 * administrator can revoke.
 */
class VaultMembershipPolicy
{
    /**
     * Accepting is the recipient confirming they verified the granter's keys.
     *
     * A membership that is already revoked cannot be accepted: the row is
     * finished, and reviving it by accepting would undo a revocation from the
     * side that revocation exists to act against.
     */
    public function accept(User $user, VaultMembership $membership): Response
    {
        $isRecipient = $membership->user_id === $user->getKey()
            && $membership->revoked_at === null
            && ! $membership->vault->trashed();

        return $isRecipient ? Response::allow() : Response::denyAsNotFound();
    }

    /**
     * Revoking removes someone else's access.
     *
     * The owner's own membership is excluded, and not as a courtesy: the Vault
     * Key exists only as the sealed copies on membership rows, so revoking the
     * last administrator's row would destroy the vault's contents with no way
     * back. The UI offers ownership transfer for that case instead.
     */
    public function revoke(User $user, VaultMembership $membership): Response
    {
        $vault = $membership->vault;

        $allowed = ! $vault->trashed()
            && $vault->roleFor($user)?->canAdminister() === true
            && $membership->revoked_at === null
            && ! $membership->role->canAdminister();

        return $allowed ? Response::allow() : Response::denyAsNotFound();
    }
}
