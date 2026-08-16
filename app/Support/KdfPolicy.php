<?php

namespace App\Support;

use App\Models\User;
use Illuminate\Support\Facades\Config;

/**
 * Whether an account's password stretching has fallen behind the deployment.
 *
 * KDF parameters are per-user columns rather than constants precisely so that
 * raising the defaults does not need a flag day (docs/03 § Parameter upgrades).
 * The cost of that is a question somebody has to answer — "is this account
 * behind?" — and this is the one place that answers it, so the login path, the
 * upgrade endpoint and `vault:health` cannot drift apart about what "behind"
 * means.
 *
 * **Compared per parameter, never as a total.** A cost function over m, t and p
 * would let a raised memory bound be satisfied by more passes, which is not the
 * same defence: memory hardness is what makes Argon2id expensive on the hardware
 * an attacker would actually rent. Each number has to meet its own target.
 */
final class KdfPolicy
{
    /** The parameters this deployment wants every account on. */
    public const KEYS = ['m', 't', 'p'];

    /**
     * @return array{m: int, t: int, p: int}
     */
    public static function target(): array
    {
        return [
            'm' => Config::integer('vault.kdf.m'),
            't' => Config::integer('vault.kdf.t'),
            'p' => Config::integer('vault.kdf.p'),
        ];
    }

    /**
     * The parameters this account should move to, or null if it is current.
     *
     * Returns the *target*, not a merge of the two. An account already above the
     * target on one number and below on another keeps the higher value, because
     * the answer is `max` per key — a "upgrade" that lowered a parameter
     * somebody had deliberately raised would be a downgrade wearing the word.
     *
     * @return array{m: int, t: int, p: int}|null
     */
    public static function upgradeFor(User $user): ?array
    {
        $current = self::paramsOf($user);
        $target = self::target();

        $wanted = [
            'm' => max($current['m'], $target['m']),
            't' => max($current['t'], $target['t']),
            'p' => max($current['p'], $target['p']),
        ];

        return $wanted === $current ? null : $wanted;
    }

    public static function isBehind(User $user): bool
    {
        return self::upgradeFor($user) !== null;
    }

    /**
     * Whether a submitted set is acceptable as a replacement for the current one.
     *
     * **An upgrade endpoint that accepts a downgrade is a downgrade endpoint.**
     * Nothing else in the system checks this: the client chooses the parameters,
     * derives at them, and posts a wrapping the server cannot inspect. If the
     * server took whatever numbers it was handed, a bug — or anything that could
     * make one request on the user's behalf — could quietly move an account to
     * 8 MiB and one pass, and every later login would happily use them.
     *
     * @param  array{m: int, t: int, p: int}  $proposed
     */
    public static function accepts(User $user, array $proposed): bool
    {
        $current = self::paramsOf($user);
        $target = self::target();

        foreach (self::KEYS as $key) {
            if ($proposed[$key] < $current[$key] || $proposed[$key] < $target[$key]) {
                return false;
            }
        }

        return true;
    }

    /**
     * The account's stored parameters, with a floor under each.
     *
     * The column is a JSON blob and its shape is only as good as whatever wrote
     * it. A missing key defaulting to 0 would make every comparison here say
     * "behind" for an account whose row is malformed, which is the right way for
     * that to fail — it prompts an upgrade rather than reading as current.
     *
     * @return array{m: int, t: int, p: int}
     */
    private static function paramsOf(User $user): array
    {
        $params = $user->kdf_params;

        return [
            'm' => is_int($params['m'] ?? null) ? $params['m'] : 0,
            't' => is_int($params['t'] ?? null) ? $params['t'] : 0,
            'p' => is_int($params['p'] ?? null) ? $params['p'] : 0,
        ];
    }
}
