<?php

namespace App\Http\Controllers\Auth;

use App\Enums\AuditAction;
use App\Http\Controllers\Controller;
use App\Models\User;
use App\Models\UserKeyWrap;
use App\Rules\Base64Bytes;
use App\Support\AuditLog;
use App\Support\DecoyHash;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Validation\ValidationException;
use Inertia\Inertia;
use Inertia\Response;

/**
 * Recovery, and the password change that follows it.
 *
 * The recovery code never reaches the server. It is split in the browser the
 * same way the password is: one half unwraps the User Key and stays there, the
 * other half is an auth key the server stores a hash of.
 *
 * That split is what makes this safe. Without it there are only bad options —
 * either the server hands the recovery wrapping to anyone who names an address
 * (letting an attacker overwrite someone's password wrapping and lock them out),
 * or it receives the code itself, which combined with the wrapped key it already
 * holds would give it the User Key outright.
 */
class RecoveryController extends Controller
{
    public function create(): Response
    {
        return Inertia::render('auth/Recover', [
            'kdfParams' => config('vault.kdf'),
        ]);
    }

    /**
     * Step one: the salt needed to derive the recovery keys.
     *
     * Answered for any address, real or not, with a stable decoy — this cannot
     * be used to discover whether an account exists (SR6).
     */
    public function salt(Request $request): JsonResponse
    {
        $request->validate([
            'email' => ['required', 'string', 'email', 'max:255'],
        ]);

        $email = $this->normalisedEmail($request);
        $wrap = $this->recoveryWrapFor($email);

        return response()->json([
            'recoverySalt' => $wrap instanceof UserKeyWrap
                ? (string) $wrap->salt
                : $this->decoySalt($email),
        ]);
    }

    /**
     * Step two: prove possession of the recovery code, and receive the wrapping.
     *
     * A successful attempt authenticates the user, because they have
     * demonstrated knowledge of a 128-bit secret only they were ever shown.
     */
    public function store(Request $request): JsonResponse
    {
        $request->validate([
            'email' => ['required', 'string', 'email', 'max:255'],
            'recovery_auth_key' => ['required', 'string', Base64Bytes::exactly(32)],
        ]);

        $key = 'recover:'.sha1((string) $request->ip());

        if (RateLimiter::tooManyAttempts($key, 5)) {
            throw ValidationException::withMessages([
                'recovery_code' => 'Too many attempts. Try again shortly.',
            ]);
        }

        RateLimiter::hit($key, 900);

        $wrap = $this->recoveryWrapFor($this->normalisedEmail($request));
        $user = $wrap?->user;

        /*
         | One generic failure whether the account is unknown, has no recovery
         | wrapping, or the code is simply wrong — and one Hash::check on every
         | one of those paths.
         |
         | The `&&` chain used to short-circuit before the hash whenever there
         | was no wrapping to check, so an address nobody has returned in about
         | a millisecond while a real one spent a quarter of a second. That made
         | this endpoint a cleaner account oracle than the login form it sits
         | beside, which is the enumeration SR6 forbids. Found by the timing
         | work in docs/07-penetration-test.md.
         */
        $decoy = DecoyHash::forVerification();

        $verified = Hash::check(
            $request->string('recovery_auth_key')->toString(),
            $wrap instanceof UserKeyWrap ? ($wrap->verifier_hash ?? $decoy) : $decoy,
        ) && $wrap instanceof UserKeyWrap && $user instanceof User;

        if (! $verified || ! $user instanceof User) {
            throw ValidationException::withMessages([
                'recovery_code' => 'That email and recovery kit combination did not work.',
            ]);
        }

        RateLimiter::clear($key);

        auth()->login($user);
        $request->session()->regenerate();

        // Marks this session as having arrived by recovery, so the password
        // change that must follow does not demand a password the user has by
        // definition forgotten. Consumed on first use.
        $request->session()->put('recovery.verified', true);

        /*
         | The single most important line this log will ever hold. Recovery is
         | the one flow that grants a session without the password, so an entry
         | nobody recognises is the strongest signal available that an account
         | has been taken — and the user is shown it on their own activity page.
         */
        AuditLog::record(AuditAction::RecoveryUsed, $user, [], $user);

        return response()->json([
            'wrappedUserKey' => $wrap->wrapped_user_key->base64,
            'userKeyAad' => [
                'context' => 'user.userkey',
                'subject' => $user->uuid,
                'version' => 1,
            ],
        ]);
    }

    /**
     * Re-wraps the User Key under a new password.
     *
     * Note what does *not* happen: no vault, lockbox, secret or identity key is
     * touched. The User Key indirection means changing a password re-wraps one
     * 32-byte key and nothing else.
     *
     * `current_auth_key` is skipped when the session was established by
     * recovery — the user has already proved themselves with the kit, and by
     * definition does not know the old password.
     */
    public function update(Request $request): JsonResponse
    {
        $request->validate([
            'current_auth_key' => ['nullable', 'string', Base64Bytes::exactly(32)],
            'kdf_salt' => ['required', 'string', Base64Bytes::exactly(16)],
            'kdf_params' => ['required', 'array'],
            'kdf_params.m' => ['required', 'integer', 'min:8192', 'max:1048576'],
            'kdf_params.t' => ['required', 'integer', 'min:2', 'max:10'],
            'kdf_params.p' => ['required', 'integer', 'min:1', 'max:4'],
            'auth_key' => ['required', 'string', Base64Bytes::exactly(32)],
            'wrapped_user_key' => ['required', 'string', Base64Bytes::between(50, 200)],

            'recovery_salt' => ['nullable', 'string', Base64Bytes::exactly(16)],
            'recovery_wrapped_user_key' => ['nullable', 'string', Base64Bytes::between(50, 200)],
            'recovery_auth_key' => ['nullable', 'string', Base64Bytes::exactly(32)],
        ]);

        $user = $this->currentUser($request);
        $viaRecovery = (bool) $request->session()->pull('recovery.verified', false);

        if (! $viaRecovery) {
            $current = $request->string('current_auth_key')->toString();

            if ($current === '' || ! Hash::check($current, $user->auth_key_hash)) {
                throw ValidationException::withMessages([
                    'current_auth_key' => 'The current password is incorrect.',
                ]);
            }
        }

        DB::transaction(function () use ($request, $user, $viaRecovery): void {
            $user->forceFill([
                'kdf_salt' => $request->string('kdf_salt')->toString(),
                'kdf_params' => $request->array('kdf_params'),
                'auth_key_hash' => Hash::make($request->string('auth_key')->toString()),
            ])->save();

            $user->keyWraps()
                ->where('method', UserKeyWrap::METHOD_PASSWORD)
                ->update(['wrapped_user_key' => $request->string('wrapped_user_key')->toString()]);

            if ($request->filled('recovery_wrapped_user_key')) {
                $this->storeRecoveryKit($request, $user);
            }

            if ($viaRecovery) {
                $user->forceFill(['recovery_used_at' => now()])->save();
            }

            AuditLog::record(AuditAction::PasswordChanged, $user, [], $user);
        });

        return response()->json(['ok' => true]);
    }

    /** Issues a fresh recovery kit, replacing whatever came before. */
    public function reissue(Request $request): JsonResponse
    {
        $request->validate([
            'recovery_salt' => ['required', 'string', Base64Bytes::exactly(16)],
            'recovery_wrapped_user_key' => ['required', 'string', Base64Bytes::between(50, 200)],
            'recovery_auth_key' => ['required', 'string', Base64Bytes::exactly(32)],
        ]);

        $user = $this->currentUser($request);

        $this->storeRecoveryKit($request, $user);

        AuditLog::record(AuditAction::RecoveryKitIssued, $user, [], $user);

        return response()->json(['ok' => true]);
    }

    private function storeRecoveryKit(Request $request, User $user): void
    {
        $user->keyWraps()->updateOrCreate(
            ['method' => UserKeyWrap::METHOD_RECOVERY, 'label' => null],
            [
                'wrapped_user_key' => $request->string('recovery_wrapped_user_key')->toString(),
                'salt' => $request->string('recovery_salt')->toString(),
                'verifier_hash' => Hash::make($request->string('recovery_auth_key')->toString()),
            ],
        );
    }

    private function recoveryWrapFor(string $email): ?UserKeyWrap
    {
        return UserKeyWrap::query()
            ->where('method', UserKeyWrap::METHOD_RECOVERY)
            ->whereHas('user', fn ($query) => $query->where('email', $email))
            ->with('user')
            ->first();
    }

    private function normalisedEmail(Request $request): string
    {
        return strtolower(trim($request->string('email')->toString()));
    }

    /** Stable, unguessable, and the same shape a real salt has. */
    private function decoySalt(string $email): string
    {
        $digest = hash_hmac('sha256', 'recovery-salt-decoy:'.$email, Config::string('app.key'), true);

        return base64_encode(substr($digest, 0, 16));
    }
}
