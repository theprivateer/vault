<?php

namespace App\Policies;

use App\Models\Secret;
use App\Models\User;
use Illuminate\Auth\Access\Response;

/**
 * A secret inherits its lockbox's vault. The chain is walked through the loaded
 * records — `secret → lockbox → vault → memberships` — so no identifier in the
 * request participates in the decision. See VaultPolicy for why every denial is
 * a 404.
 */
class SecretPolicy
{
    public function view(User $user, Secret $secret): Response
    {
        return $this->reachable($secret) && $secret->lockbox->vault->roleFor($user) !== null
            ? Response::allow()
            : Response::denyAsNotFound();
    }

    public function update(User $user, Secret $secret): Response
    {
        return $this->reachable($secret) && $secret->lockbox->vault->roleFor($user)?->canWrite() === true
            ? Response::allow()
            : Response::denyAsNotFound();
    }

    /**
     * Whether the whole chain above this secret is still live.
     *
     * Soft-deleting a lockbox or a vault leaves its secrets as routable rows
     * until the purge job runs. A UUID captured before a delete must not still
     * open afterwards.
     */
    private function reachable(Secret $secret): bool
    {
        return ! $secret->lockbox->trashed() && ! $secret->lockbox->vault->trashed();
    }

    public function delete(User $user, Secret $secret): Response
    {
        return $this->update($user, $secret);
    }
}
