<?php

namespace App\Http\Controllers;

use App\Models\User;
use App\Models\Vault;
use App\Models\VaultMembership;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Foundation\Auth\Access\AuthorizesRequests;
use Illuminate\Http\Request;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

abstract class Controller
{
    use AuthorizesRequests;

    /**
     * The authenticated user, as a User rather than a nullable Authenticatable.
     *
     * The `auth` middleware already guarantees this, but the guarantee is
     * invisible to static analysis — and a route accidentally registered
     * outside that middleware would otherwise fail with a confusing null error
     * deep in a transaction rather than an authentication failure here.
     */
    protected function currentUser(Request $request): User
    {
        $user = $request->user();

        if (! $user instanceof User) {
            throw new AuthenticationException;
        }

        return $user;
    }

    /**
     * The current user's live membership of a vault.
     *
     * Narrows what a policy has already established. `view` passing means a
     * live membership exists — but that is a fact about control flow rather
     * than about types, and a route accidentally registered without its policy
     * should 404 here rather than dereference null.
     */
    protected function membershipFor(Vault $vault, Request $request): VaultMembership
    {
        $membership = $vault->membershipFor($this->currentUser($request));

        if ($membership === null) {
            throw new NotFoundHttpException;
        }

        return $membership;
    }
}
