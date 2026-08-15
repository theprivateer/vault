<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\JsonResponse;

/**
 * Looking somebody up in order to share with them.
 *
 * This endpoint hands out public keys, and it is the exact point at which a
 * malicious server would substitute its own. Nothing here can prevent that —
 * the server is the one answering — so the design does not pretend otherwise.
 * What it does is give the browser everything it needs to detect it: the two
 * public keys, the self-signature proving they were published together, and the
 * fingerprint the user compares out of band and pins.
 *
 * The honest summary is that this response is untrusted input which the client
 * treats as a claim, not a fact. See docs/03 § Sharing a vault.
 */
class UserIdentityController extends Controller
{
    /**
     * Resolves a handle to a public key bundle.
     *
     * **This is a directory, and directories enumerate.** Any authenticated user
     * can discover whether a handle exists, which is a deliberate acceptance
     * rather than an oversight: sharing by handle requires exactly that lookup,
     * and D11 scopes this to a small invited group where the membership list is
     * not the secret. The rate limit is on the route. An account with no
     * published keys answers 404 like an unknown one — it cannot be shared with
     * either way, and two different negatives would be a distinction worth
     * probing for.
     */
    public function show(string $handle): JsonResponse
    {
        $user = User::query()
            ->with('identity')
            ->where('handle', $handle)
            ->first();

        abort_if($user?->identity === null, 404);

        return response()->json([
            'uuid' => $user->uuid,
            'displayName' => $user->display_name,
            'handle' => $user->handle,
            ...$user->identity->toPublicBundle(),
        ]);
    }
}
