<?php

namespace App\Http\Middleware;

use App\Models\User;
use Illuminate\Http\Request;
use Inertia\Middleware;

class HandleInertiaRequests extends Middleware
{
    /**
     * The root template that's loaded on the first page visit.
     *
     * @see https://inertiajs.com/server-side-setup#root-template
     *
     * @var string
     */
    protected $rootView = 'app';

    /**
     * Determines the current asset version.
     *
     * @see https://inertiajs.com/asset-versioning
     */
    public function version(Request $request): ?string
    {
        return parent::version($request);
    }

    /**
     * Define the props that are shared by default.
     *
     * @see https://inertiajs.com/shared-data
     *
     * @return array<string, mixed>
     */
    public function share(Request $request): array
    {
        $user = $request->user();

        return [
            ...parent::share($request),
            'auth' => [
                /*
                 | Only what the interface needs to render. Nothing here is
                 | secret, and nothing here can decrypt anything — but there is
                 | no reason to ship more than the shell requires.
                 */
                'user' => $user?->only(['uuid', 'display_name', 'handle', 'email']),

                /*
                 | The unlock bundle travels with every authenticated page,
                 | because the server cannot tell whether the browser is
                 | unlocked — that state lives entirely in the Worker, and a
                 | full page reload destroys it. Shipping it here means any page
                 | can offer the unlock prompt without a round trip.
                 |
                 | Safe to hand over: without the password it is inert.
                 */
                'bundle' => $user instanceof User ? $user->unlockBundle() : null,

                /*
                 | The user's own identity, private halves included — still
                 | encrypted under their User Key. The browser cannot open a
                 | vault without them, since every Vault Key arrives as a sealed
                 | box addressed to that X25519 key.
                 */
                'identity' => $user instanceof User ? $user->identity?->toOwnerBundle() : null,

                /*
                 | The encrypted record of whose public keys this user has
                 | verified, alongside the identity it is opened with.
                 |
                 | Shared rather than fetched per page because every fingerprint
                 | decision is made against it, and a page that rendered a
                 | "verified" badge before the store arrived would be showing an
                 | answer it did not have yet. A null blob means nobody has been
                 | verified, which is a real state and not an error.
                 */
                'pins' => $user instanceof User ? $user->pinBundle() : null,
            ],
        ];
    }
}
