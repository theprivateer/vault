<?php

namespace App\Policies;

use App\Models\User;
use App\Models\Vault;
use Illuminate\Auth\Access\Response;

/**
 * Authorisation for vaults, and the template for the rest.
 *
 * Two rules run through every policy here:
 *
 * 1. **Access is a live `vault_memberships` row.** Never a `vault_id` from the
 *    request, never ownership inferred from a foreign key on the resource
 *    itself. The membership table is the only source of truth.
 *
 * 2. **Denial is 404, not 403.** A 403 confirms the record exists, which hands
 *    an attacker a working existence oracle over UUIDs they should know nothing
 *    about. `denyAsNotFound()` makes someone else's vault indistinguishable
 *    from one that was never there.
 */
class VaultPolicy
{
    public function view(User $user, Vault $vault): Response
    {
        return $vault->roleFor($user) !== null
            ? Response::allow()
            : Response::denyAsNotFound();
    }

    /**
     * A viewer is blocked from every write path.
     *
     * Worth being honest about what this achieves: it prevents a viewer from
     * *changing* the vault. It does not and cannot prevent them reading it —
     * they hold the Vault Key, so they can decrypt whatever they can fetch.
     */
    public function update(User $user, Vault $vault): Response
    {
        return $vault->roleFor($user)?->canWrite() === true
            ? Response::allow()
            : Response::denyAsNotFound();
    }

    public function delete(User $user, Vault $vault): Response
    {
        return $vault->roleFor($user)?->canAdminister() === true
            ? Response::allow()
            : Response::denyAsNotFound();
    }

    /**
     * Granting access to somebody else.
     *
     * Administrators only — an editor may change what is in the vault, but not
     * who can read it. The two are genuinely different powers: content can be
     * corrected, and a copy of the Vault Key handed to a stranger cannot be
     * taken back (see `rekey`).
     */
    public function share(User $user, Vault $vault): Response
    {
        return $vault->roleFor($user)?->canAdminister() === true
            ? Response::allow()
            : Response::denyAsNotFound();
    }

    /**
     * Changing how long the vault keeps superseded payloads.
     *
     * An administrator ability rather than a write one, because shortening
     * retention destroys history for everybody in the vault and lengthening it
     * keeps everybody's old credentials on the server for longer. An editor may
     * change what a secret says; deciding how long the previous answers survive
     * is a policy about other people's data.
     */
    public function configure(User $user, Vault $vault): Response
    {
        return $vault->roleFor($user)?->canAdminister() === true
            ? Response::allow()
            : Response::denyAsNotFound();
    }

    /**
     * Rotating the Vault Key, which is the second half of revocation.
     *
     * Restricted to administrators for the same reason as `share`, and because a
     * re-key rewrites every wrapped key in the vault: a client that got it wrong
     * would leave members holding keys that open nothing.
     */
    public function rekey(User $user, Vault $vault): Response
    {
        return $vault->roleFor($user)?->canAdminister() === true
            ? Response::allow()
            : Response::denyAsNotFound();
    }
}
