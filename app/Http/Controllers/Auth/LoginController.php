<?php

namespace App\Http\Controllers\Auth;

use App\Enums\AuditAction;
use App\Http\Controllers\Controller;
use App\Http\Requests\Auth\LoginRequest;
use App\Models\User;
use App\Support\AuditLog;
use App\Support\KdfPolicy;
use App\Support\Totp;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Validation\ValidationException;
use Inertia\Inertia;
use Inertia\Response;

/**
 * Authentication.
 *
 * Succeeding here gets you a session, not a vault: the response carries the
 * *wrapped* User Key, which only the client's KEK can open. A server that
 * wanted to impersonate a user could hand out a session, and would still not be
 * able to read a single secret.
 */
class LoginController extends Controller
{
    public function create(): Response
    {
        return Inertia::render('auth/Login');
    }

    public function store(LoginRequest $request): JsonResponse
    {
        $email = $request->string('email')->toString();

        $this->ensureNotThrottled($request, $email);

        $user = User::query()->where('email', $email)->first();

        /*
         | One generic failure for every cause: unknown address, wrong password,
         | wrong second factor. Anything more specific tells an attacker which
         | half of the guess was right.
         |
         | Hash::check is run even when there is no user, against a dummy hash,
         | so a missing account does not return measurably faster than a wrong
         | password.
         */
        $authenticated = $user
            ? Hash::check($request->string('auth_key')->toString(), $user->auth_key_hash)
            : $this->burnTime($request->string('auth_key')->toString());

        if (! $user || ! $authenticated || ! $this->passesSecondFactor($user, $request)) {
            RateLimiter::hit($this->ipKey($request));
            RateLimiter::hit($this->accountKey($email));

            /*
             | Recorded with no actor when the address belongs to nobody, and
             | with one when it does. The email itself is deliberately absent:
             | an audit log full of attempted addresses would be a list of who
             | has an account here, assembled by whoever was guessing. The
             | `ip_hash` is what correlates a sweep.
             */
            AuditLog::record(AuditAction::LoginFailed, $user, [], $user);

            throw ValidationException::withMessages([
                'email' => 'Those credentials do not match our records.',
            ]);
        }

        RateLimiter::clear($this->ipKey($request));
        RateLimiter::clear($this->accountKey($email));

        auth()->login($user);
        $request->session()->regenerate();

        $user->forceFill(['last_login_at' => now()])->save();

        AuditLog::record(
            AuditAction::LoggedIn,
            $user,
            ['second_factor' => $user->hasTotpEnabled()],
            $user,
        );

        return response()->json([
            'redirect' => route('vaults.index'),
            'bundle' => $user->unlockBundle(),

            /*
             | The parameters this account should move to, or null (Phase 10).
             |
             | Answered here rather than left to the client to work out, because
             | the client would have to be told the deployment default anyway and
             | then two places would decide what "behind" means. Login is also
             | the only moment the upgrade is possible: it needs the password,
             | and the password exists in the browser for the length of this one
             | form submission.
             */
            'kdfUpgrade' => KdfPolicy::upgradeFor($user),
        ]);
    }

    public function destroy(Request $request): RedirectResponse
    {
        // Before the logout, while there is still a user to attribute it to.
        AuditLog::record(AuditAction::LoggedOut, $request->user());

        auth()->logout();

        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return redirect()->route('login');
    }

    /**
     * The second factor, when enrolled.
     *
     * A backup code is accepted in place of a TOTP code and is burned on use.
     */
    private function passesSecondFactor(User $user, LoginRequest $request): bool
    {
        if (! $user->hasTotpEnabled()) {
            return true;
        }

        $submitted = $request->string('totp_code')->toString();

        if ($submitted === '') {
            return false;
        }

        if (Totp::verify((string) $user->totp_secret_ct, $submitted)) {
            return true;
        }

        return $this->consumeBackupCode($user, $submitted);
    }

    private function consumeBackupCode(User $user, string $submitted): bool
    {
        foreach ($user->backupCodes()->whereNull('used_at')->get() as $code) {
            if (Hash::check($submitted, $code->code_hash)) {
                $code->forceFill(['used_at' => now()])->save();

                return true;
            }
        }

        return false;
    }

    /**
     * Spends roughly the time a real verification would, so that "no such
     * account" and "wrong password" are not distinguishable by a stopwatch.
     */
    private function burnTime(string $authKey): bool
    {
        Hash::check($authKey, Hash::make('decoy'));

        return false;
    }

    private function ensureNotThrottled(Request $request, string $email): void
    {
        $limit = Config::integer('vault.throttle.login_per_minute');

        foreach ([$this->ipKey($request), $this->accountKey($email)] as $key) {
            if (RateLimiter::tooManyAttempts($key, $limit)) {
                throw ValidationException::withMessages([
                    'email' => 'Too many attempts. Try again in '
                        .ceil(RateLimiter::availableIn($key) / 60).' minutes.',
                ]);
            }
        }
    }

    private function ipKey(Request $request): string
    {
        return 'login:ip:'.sha1((string) $request->ip());
    }

    /**
     * Hashed so the rate-limit store does not become a list of who has been
     * trying to sign in.
     */
    private function accountKey(string $email): string
    {
        return 'login:account:'.hash_hmac('sha256', $email, Config::string('app.key'));
    }
}
