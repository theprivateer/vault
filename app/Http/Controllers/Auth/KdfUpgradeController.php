<?php

namespace App\Http\Controllers\Auth;

use App\Enums\AuditAction;
use App\Http\Controllers\Controller;
use App\Models\UserKeyWrap;
use App\Rules\Base64Bytes;
use App\Support\AuditLog;
use App\Support\KdfPolicy;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;

/**
 * Re-stretching a password at raised Argon2id parameters.
 *
 * The mechanics are a password change that keeps the password: a fresh salt, a
 * re-derived KEK, the same User Key re-wrapped under it, and a new auth key.
 * Nothing is re-encrypted — the User Key does not change, so every vault key,
 * identity key and payload is untouched. That indirection is exactly what this
 * endpoint exists to cash in (docs/03 § Parameter upgrades).
 *
 * **It requires the current auth key, and that is not ceremony.** Without it
 * this endpoint would be a straightforward account takeover from a session
 * alone: injected script asks the Worker to re-wrap the User Key under a
 * password of its choosing, posts the result, and the account's password is now
 * one the attacker picked. The wrapping is opaque here, so the server cannot
 * tell that request from a genuine upgrade by looking at it. Proof of the
 * current password is the only thing that separates them, which is the same
 * reason the password-change endpoint demands one.
 *
 * The parameters are checked as well as the credential — see `KdfPolicy::accepts`
 * — because an upgrade endpoint that accepts a downgrade is a downgrade endpoint.
 */
class KdfUpgradeController extends Controller
{
    public function __invoke(Request $request): JsonResponse
    {
        $request->validate([
            'current_auth_key' => ['required', 'string', Base64Bytes::exactly(32)],
            'kdf_salt' => ['required', 'string', Base64Bytes::exactly(16)],
            'kdf_params' => ['required', 'array'],
            'kdf_params.m' => ['required', 'integer', 'min:8192', 'max:1048576'],
            'kdf_params.t' => ['required', 'integer', 'min:2', 'max:10'],
            'kdf_params.p' => ['required', 'integer', 'min:1', 'max:4'],
            'auth_key' => ['required', 'string', Base64Bytes::exactly(32)],
            'wrapped_user_key' => ['required', 'string', Base64Bytes::between(50, 200)],
        ]);

        $user = $this->currentUser($request);

        if (! Hash::check($request->string('current_auth_key')->toString(), $user->auth_key_hash)) {
            throw ValidationException::withMessages([
                'current_auth_key' => 'The current password is incorrect.',
            ]);
        }

        /** @var array{m: int, t: int, p: int} $params */
        $params = $request->array('kdf_params');

        if (! KdfPolicy::accepts($user, $params)) {
            throw ValidationException::withMessages([
                'kdf_params' => 'Those parameters are weaker than this account already uses, or weaker '
                    .'than this deployment requires. Nothing was changed.',
            ]);
        }

        DB::transaction(function () use ($request, $user, $params): void {
            $user->forceFill([
                'kdf_salt' => $request->string('kdf_salt')->toString(),
                'kdf_params' => $params,
                'auth_key_hash' => Hash::make($request->string('auth_key')->toString()),
            ])->save();

            /*
             | Only the password wrapping. The recovery wrapping derives its KEK
             | from the recovery code and its own salt, so it is unaffected by
             | the password's parameters — re-wrapping it here would need the
             | recovery code, which nobody has at login time and the server must
             | never see.
             */
            $user->keyWraps()
                ->where('method', UserKeyWrap::METHOD_PASSWORD)
                ->update(['wrapped_user_key' => $request->string('wrapped_user_key')->toString()]);

            /*
             | Logged even though it is invisible to the user. It changes the
             | stored authentication material, so an entry here is what lets
             | somebody reading the log afterwards tell a silent upgrade from
             | a password change they did not make.
             */
            AuditLog::record(AuditAction::KdfUpgraded, $user, [
                'kdf_m' => $params['m'],
                'kdf_t' => $params['t'],
                'kdf_p' => $params['p'],
            ], $user);
        });

        return response()->json(['ok' => true]);
    }
}
