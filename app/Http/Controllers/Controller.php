<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Http\Request;

abstract class Controller
{
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
}
