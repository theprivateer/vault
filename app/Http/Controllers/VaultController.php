<?php

namespace App\Http\Controllers;

use App\Http\Controllers\Auth\LoginController;
use Illuminate\Http\Request;
use Inertia\Inertia;
use Inertia\Response;

/**
 * The signed-in landing page.
 *
 * It always ships the unlock bundle, because the server cannot tell whether the
 * client is unlocked — that state lives entirely in the browser's Worker. A
 * full page reload loses the Worker, so the bundle has to be here for the
 * client to unlock again without a round trip.
 *
 * Handing it over is safe: without the password it is inert.
 */
class VaultController extends Controller
{
    public function index(Request $request): Response
    {
        $user = $this->currentUser($request);

        return Inertia::render('Vault', [
            'bundle' => LoginController::unlockBundle($user),
            'identity' => $user->identity?->toPublicBundle(),
            'twoFactorEnabled' => $user->hasTotpEnabled(),
        ]);
    }
}
