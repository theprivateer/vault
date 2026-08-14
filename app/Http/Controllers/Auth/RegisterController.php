<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Http\Requests\Auth\RegisterRequest;
use App\Models\Invite;
use App\Models\User;
use App\Models\UserKeyWrap;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Inertia\Inertia;
use Inertia\Response;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

/**
 * Account creation.
 *
 * Every key in the payload was generated in the browser. The server stores
 * blobs, hashes the auth key, and learns nothing it could use to read a vault.
 */
class RegisterController extends Controller
{
    public function create(string $token): Response
    {
        $invite = $this->resolveInvite($token);

        return Inertia::render('auth/Register', [
            'token' => $token,
            'email' => $invite->email,
            // The client needs these to stretch the password. Not secret.
            'kdfParams' => config('vault.kdf'),
        ]);
    }

    public function store(RegisterRequest $request, string $token): JsonResponse
    {
        $invite = $this->resolveInvite($token);

        $user = DB::transaction(function () use ($request, $invite): User {
            $user = User::create([
                'uuid' => $request->string('uuid')->toString(),
                'email' => $invite->email,
                'display_name' => $request->string('display_name')->toString(),
                'handle' => $request->string('handle')->toString(),
                'kdf_salt' => $request->string('kdf_salt')->toString(),
                'kdf_algorithm' => 'argon2id',
                'kdf_params' => $request->array('kdf_params'),
                'auth_key_hash' => Hash::make($request->string('auth_key')->toString()),
            ]);

            /*
             | Two independent wrappings of the same User Key: one openable with
             | the password, one with the recovery code. The server holds
             | neither key, so it can open neither.
             */
            $user->keyWraps()->createMany([
                [
                    'method' => UserKeyWrap::METHOD_PASSWORD,
                    'wrapped_user_key' => $request->string('wrapped_user_key')->toString(),
                ],
                [
                    'method' => UserKeyWrap::METHOD_RECOVERY,
                    'wrapped_user_key' => $request->string('recovery_wrapped_user_key')->toString(),
                    'salt' => $request->string('recovery_salt')->toString(),
                    'verifier_hash' => Hash::make($request->string('recovery_auth_key')->toString()),
                ],
            ]);

            $user->identity()->create([
                'x25519_public_key' => $request->string('x25519_public_key')->toString(),
                'ed25519_public_key' => $request->string('ed25519_public_key')->toString(),
                'x25519_private_key_ct' => $request->string('x25519_private_key_ct')->toString(),
                'ed25519_private_key_ct' => $request->string('ed25519_private_key_ct')->toString(),
                'self_signature' => $request->string('self_signature')->toString(),
                'fingerprint' => $request->string('fingerprint')->toString(),
            ]);

            $invite->forceFill(['accepted_at' => now()])->save();

            return $user;
        });

        auth()->login($user);
        $request->session()->regenerate();

        return response()->json(['redirect' => route('vaults.index')]);
    }

    /**
     * Invitations are looked up by hash, so a leaked database yields no usable
     * links. An invalid or spent token is a 404 rather than a 403: there is no
     * reason to confirm that a token ever existed.
     */
    private function resolveInvite(string $token): Invite
    {
        $invite = Invite::query()
            ->usable()
            ->where('token_hash', Invite::hashToken($token))
            ->first();

        if (! $invite) {
            throw new NotFoundHttpException('This invitation is not valid.');
        }

        return $invite;
    }
}
