<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Support\Totp;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;
use Inertia\Inertia;
use Inertia\Response;

/**
 * Enrolment for the TOTP second factor.
 *
 * Worth restating where a reader will see it: this protects **authentication**
 * only. It makes a stolen password less useful for obtaining a session. It does
 * not stand between anyone and a vault, because unlocking a vault never
 * involves the server.
 */
class TotpController extends Controller
{
    private const PENDING_SECRET = 'totp.pending_secret';

    private const BACKUP_CODE_COUNT = 8;

    public function create(Request $request): Response
    {
        $user = $this->currentUser($request);

        if ($user->hasTotpEnabled()) {
            return Inertia::render('account/TwoFactor', ['enabled' => true]);
        }

        // Held in the session until a valid code proves the authenticator has
        // it too. An unconfirmed secret is never written to the user record.
        $secret = Totp::generateSecret();
        $request->session()->put(self::PENDING_SECRET, $secret);

        return Inertia::render('account/TwoFactor', [
            'enabled' => false,
            'secret' => $secret,
            'groupedSecret' => trim(chunk_split($secret, 4, ' ')),
            'uri' => Totp::provisioningUri($secret, $user->email, Config::string('app.name')),
        ]);
    }

    public function store(Request $request): JsonResponse
    {
        $request->validate([
            'code' => ['required', 'string', 'max:20'],
        ]);

        $user = $this->currentUser($request);
        $secret = $request->session()->get(self::PENDING_SECRET);

        // An absent or malformed pending secret means enrolment was never
        // started in this session, which is a failure like any other.
        if (! is_string($secret) || $secret === '' || ! Totp::verify($secret, $request->string('code')->toString())) {
            throw ValidationException::withMessages([
                'code' => 'That code is not valid. Check your authenticator and try again.',
            ]);
        }

        $codes = collect(range(1, self::BACKUP_CODE_COUNT))
            ->map(fn (): string => Totp::generateBackupCode());

        DB::transaction(function () use ($user, $secret, $codes): void {
            $user->forceFill([
                'totp_secret_ct' => $secret,
                'totp_confirmed_at' => now(),
            ])->save();

            $user->backupCodes()->delete();
            $user->backupCodes()->createMany(
                $codes->map(fn (string $code): array => ['code_hash' => Hash::make($code)])->all()
            );
        });

        $request->session()->forget(self::PENDING_SECRET);

        // Shown once. Only hashes are kept.
        return response()->json(['backupCodes' => $codes->all()]);
    }

    public function destroy(Request $request): JsonResponse
    {
        $user = $this->currentUser($request);

        DB::transaction(function () use ($user): void {
            $user->forceFill(['totp_secret_ct' => null, 'totp_confirmed_at' => null])->save();
            $user->backupCodes()->delete();
        });

        return response()->json(['ok' => true]);
    }
}
