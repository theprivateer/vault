<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Nothing this application receives may be flashed back into the session.
 *
 * Laravel turns a `ValidationException` into a redirect carrying the request
 * body, so the user does not retype a form. That is the wrong trade here twice
 * over. Every write in this application carries ciphertext and wrapped key
 * material — `payload_ct`, `wrapped_item_key`, `version_wrapped_item_key` — and
 * a concurrent-edit conflict is a *validation error* by design
 * (.ai/rules/controllers.md), so the routine case of two tabs open on one
 * secret was writing two payloads and two wrapped Item Keys into the session
 * store. The session is encrypted at rest, under a key the server holds, which
 * is precisely the protection the wrapping exists to not depend on.
 *
 * **Why this replaced the `dontFlash` list it grew out of.** That list was
 * written in Phase 0 against fields that did not exist yet, and by Phase 11
 * three of its seven entries — `current_password`, `master_password`,
 * `recovery_code` — named nothing in the codebase, while every field that had
 * arrived since was missing from it. An allow-list of field names cannot track a
 * schema; it can only look like it does. So the rule is not "name the sensitive
 * fields", it is **flash nothing**, which cannot drift because there is nothing
 * to keep up to date.
 *
 * Costless here: no Blade template calls `old()`, and the only view is the
 * Inertia shell. Vue form state lives in the component, which survives a failed
 * submit without the server's help.
 */
class ForgetFlashedInput
{
    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $response = $next($request);

        /*
         | After the response, so that whatever built it — the exception
         | handler's `withInput()`, or any future `$request->flash()` — has
         | already run. Appended to the `web` group, so this unwinds before
         | StartSession persists the session and the values never reach the
         | driver at all.
         |
         | `errors` is untouched: it is how the client learns what was wrong,
         | it holds messages rather than submitted values, and Inertia shares
         | it on every response.
         */
        if ($request->hasSession()) {
            $request->session()->forget('_old_input');
        }

        return $response;
    }
}
