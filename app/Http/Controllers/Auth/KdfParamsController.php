<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;

/**
 * Returns the KDF salt and parameters a client needs to derive its keys.
 *
 * This endpoint has to answer before authentication — the client cannot prove
 * who it is without first deriving an auth key, and it cannot derive one
 * without the salt. That makes it an obvious user-enumeration oracle, so an
 * unknown address gets a deterministic decoy rather than a different answer:
 * same shape, same work, same latency, stable across requests so that repeating
 * the question does not reveal anything either.
 *
 * See SR6 in docs/02-threat-model.md.
 */
class KdfParamsController extends Controller
{
    public function __invoke(Request $request): JsonResponse
    {
        $request->validate([
            'email' => ['required', 'string', 'email', 'max:255'],
        ]);

        $email = strtolower(trim($request->string('email')->toString()));

        $user = User::query()->where('email', $email)->first();

        if ($user instanceof User) {
            return response()->json([
                'kdfSalt' => $user->kdf_salt,
                'kdfParams' => $user->kdf_params,
            ]);
        }

        return response()->json([
            'kdfSalt' => $this->decoySalt($email),
            'kdfParams' => config('vault.kdf'),
        ]);
    }

    /**
     * A salt that is indistinguishable from a real one: 16 bytes, stable for a
     * given address, and unguessable without the application key.
     */
    private function decoySalt(string $email): string
    {
        $digest = hash_hmac('sha256', 'kdf-salt-decoy:'.$email, Config::string('app.key'), true);

        return base64_encode(substr($digest, 0, 16));
    }
}
