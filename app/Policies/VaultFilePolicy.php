<?php

namespace App\Policies;

use App\Models\User;
use App\Models\VaultFile;
use Illuminate\Auth\Access\Response;

/**
 * A file inherits its lockbox's vault, walked through the loaded records —
 * `file → lockbox → vault → memberships` — with nothing from the request
 * participating. See VaultPolicy for why every denial is a 404.
 */
class VaultFilePolicy
{
    public function view(User $user, VaultFile $file): Response
    {
        return $this->reachable($file) && $file->lockbox->vault->roleFor($user) !== null
            ? Response::allow()
            : Response::denyAsNotFound();
    }

    /**
     * Uploading a chunk is a write, so a viewer cannot do it.
     *
     * The check has to exist on this route in its own right and not just on the
     * one that created the row: a file with chunks still missing is the one
     * state where a stranger's write would land on somebody else's record
     * rather than creating their own.
     */
    public function update(User $user, VaultFile $file): Response
    {
        return $this->reachable($file) && $file->lockbox->vault->roleFor($user)?->canWrite() === true
            ? Response::allow()
            : Response::denyAsNotFound();
    }

    public function delete(User $user, VaultFile $file): Response
    {
        return $this->update($user, $file);
    }

    /** Whether the whole chain above this file is still live. */
    private function reachable(VaultFile $file): bool
    {
        return ! $file->lockbox->trashed() && ! $file->lockbox->vault->trashed();
    }
}
