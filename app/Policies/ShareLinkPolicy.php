<?php

namespace App\Policies;

use App\Models\ShareLink;
use App\Models\User;
use Illuminate\Auth\Access\Response;

/**
 * Who may end a share link early.
 *
 * The creator, and an administrator of the vault the secret came from. The
 * second case is the one worth having: an editor who shared something they
 * should not have is exactly the situation an owner needs to be able to
 * withdraw, and waiting for the link to expire is not a remedy.
 *
 * A link whose secret has been deleted keeps working by design, and at that
 * point only its creator can revoke it — there is no vault left to administer.
 *
 * Denial is 404 as everywhere else: a 403 would confirm that a link exists.
 */
class ShareLinkPolicy
{
    public function revoke(User $user, ShareLink $link): Response
    {
        if ($link->created_by === $user->getKey()) {
            return Response::allow();
        }

        $vault = $link->secret?->lockbox->vault;

        return $vault?->roleFor($user)?->canAdminister() === true
            ? Response::allow()
            : Response::denyAsNotFound();
    }
}
