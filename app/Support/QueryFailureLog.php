<?php

namespace App\Support;

use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\Log;

/**
 * Reports a failed query without its bindings (Phase 12, task 5).
 *
 * `QueryException::getMessage()` is built by substituting the bindings into the
 * statement, so the default report of a failed write puts every value the query
 * carried into a log file. On a secret write those values are the payload
 * ciphertext and the wrapped Item Key; on a membership write, a sealed Vault
 * Key. Nothing in the application asked for that, and nothing in the application
 * would have had to change for it to keep happening — which is what makes it the
 * kind of leak review does not find.
 *
 * **This is not a list of sensitive fields, and it must not become one.** The
 * lesson of F11 (docs/07) was that an enumerated list drifts silently and a
 * stale one reads exactly like a current one. The rule here has no list to keep
 * in step: *no binding is ever logged*. A column added tomorrow is covered
 * because nothing is exempt rather than because somebody remembered.
 *
 * What survives is everything needed to diagnose the failure — the statement
 * with its placeholders intact, the driver's own reason, the connection, and the
 * trace. The one thing lost is the values, which are the one thing a log has no
 * business holding.
 *
 * **Ciphertext rather than plaintext, and still worth closing.** The server
 * cannot read any of it, so this is not the disclosure the leak canary hunts.
 * But logs travel differently from a database: they are shipped to error
 * trackers, tailed over somebody's shoulder, attached to support threads and
 * backed up on their own schedule. A store that holds wrapped key material is a
 * store that has to be defended like the database, and the cheaper answer is for
 * it not to hold any.
 */
final class QueryFailureLog
{
    /**
     * Logs the failure and reports whether the default handler should also run.
     *
     * Always false: letting the framework log it afterwards would write the
     * message this class exists to avoid, immediately below the safe one.
     */
    public static function record(QueryException $exception): bool
    {
        $previous = $exception->getPrevious();

        Log::error('A database query failed. Bindings are omitted deliberately.', [
            /*
             | The statement with `?` where the values were — which is the half
             | that says what went wrong. "insert into secrets … has no column
             | named payload_ct" is a complete diagnosis; the value that would
             | have gone into that column adds nothing to it.
             */
            'sql' => $exception->getSql(),
            'bindings' => count($exception->getBindings()).' omitted',
            'connection' => $exception->getConnectionName(),

            /*
             | The driver's message rather than the exception's. They differ in
             | exactly one respect: PDO's carries no SQL tail, because PDO never
             | saw the interpolated statement. Falling back to the exception's
             | own message would reintroduce the bindings on any driver that
             | does not populate a previous exception, so the fallback says
             | nothing instead — a missing reason is a smaller problem than a
             | logged secret.
             */
            'reason' => $previous?->getMessage() ?? 'unavailable without exposing bindings',

            /*
             | `getTraceAsString()` truncates string arguments to 15 characters
             | and renders arrays as `Array`, so it cannot carry a binding. That
             | is PHP's own formatting rather than anything arranged here — and
             | it is why `zend.exception_ignore_args` must stay enabled, which
             | `vault:preflight` checks.
             */
            'trace' => $exception->getTraceAsString(),
        ]);

        return false;
    }
}
