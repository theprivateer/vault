<?php

namespace App\Support;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Hash;

/**
 * A password hash that nothing will ever match, for the branch where there is
 * no real one to check against.
 *
 * Every credential endpoint has two paths: the address exists, so there is a
 * stored hash to verify against, and it does not, so there is nothing. Written
 * naturally, the second path returns immediately — and the difference is
 * measurable from outside, because the first path deliberately spends a quarter
 * of a second. That turns an endpoint that answers "those credentials do not
 * match" into one that answers "no such account", which is exactly the
 * distinction SR6 in docs/02-threat-model.md says it must not draw.
 *
 * So the missing path verifies against this instead. It cannot succeed — it is
 * a hash of 32 random bytes that were discarded — but it costs what a real
 * verification costs, which is the whole point.
 *
 * Generated for the configured driver rather than hard-coded, because a
 * hard-coded bcrypt string throws outright once `hashing.driver` is argon2id
 * and `hashing.*.verify` is on.
 *
 * Held twice over — in the cache, and in a static for the life of the process —
 * because generating one costs exactly what verifying one costs. Regenerating
 * per request would put the missing-account path back to two hashes against the
 * real path's one, which is the divergence this class exists to remove.
 *
 * Callers should resolve it unconditionally rather than only on the branch that
 * needs it, so that both branches pay the same lookup.
 */
final class DecoyHash
{
    private const CACHE_KEY = 'auth:decoy-hash';

    /**
     * Held for the life of the process, in front of the cache.
     *
     * The cache is what makes this survive a worker restart: without it, the
     * first unknown address seen by each fresh process would pay for a hash
     * that later ones do not. With it, that happens once for the deployment
     * rather than once per worker.
     */
    private static ?string $hash = null;

    /**
     * Callers must still refuse the request on their own terms. Verifying
     * against this returns false, but it returns false for the same reason a
     * wrong password does, so nothing downstream should read it as proof that
     * an account exists.
     */
    public static function forVerification(): string
    {
        return self::$hash ??= Cache::rememberForever(
            self::CACHE_KEY,
            /*
             | The input is thrown away deliberately. Nothing needs to verify
             | against this hash — it exists to be compared with and to fail —
             | so the safest possible preimage is one that never existed
             | anywhere outside this expression.
             */
            fn (): string => Hash::make(base64_encode(random_bytes(32))),
        );
    }
}
