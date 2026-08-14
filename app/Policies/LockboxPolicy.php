<?php

namespace App\Policies;

use App\Models\Lockbox;
use App\Models\User;
use Illuminate\Auth\Access\Response;

/**
 * A lockbox inherits its vault's authorisation, resolved through the record
 * rather than through anything the request said. See VaultPolicy for why every
 * denial is a 404.
 */
class LockboxPolicy
{
    public function view(User $user, Lockbox $lockbox): Response
    {
        return ! $lockbox->vault->trashed() && $lockbox->vault->roleFor($user) !== null
            ? Response::allow()
            : Response::denyAsNotFound();
    }

    /**
     * The deleted check is not incidental.
     *
     * Deleting a vault soft-deletes it, which hides the vault but leaves its
     * lockboxes and secrets as live, routable rows for the length of the grace
     * period. Without this, a UUID captured before the delete would still open.
     */
    public function update(User $user, Lockbox $lockbox): Response
    {
        return ! $lockbox->vault->trashed() && $lockbox->vault->roleFor($user)?->canWrite() === true
            ? Response::allow()
            : Response::denyAsNotFound();
    }

    public function delete(User $user, Lockbox $lockbox): Response
    {
        return $this->update($user, $lockbox);
    }
}
