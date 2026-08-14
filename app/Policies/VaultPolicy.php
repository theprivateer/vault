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
}
