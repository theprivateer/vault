<?php

namespace App\Http\Controllers;

use Symfony\Component\HttpFoundation\BinaryFileResponse;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

/**
 * Serves the crypto Worker script (docs/07 F13).
 *
 * The Worker lived in `public/build/` until the first deployment, where nginx
 * served it directly — which meant it arrived with no security headers at all.
 * That is not merely untidy: a document sending
 * `Cross-Origin-Embedder-Policy: require-corp` may only create a dedicated
 * worker whose **own response** carries a compatible COEP, so the browser
 * refused to load it and nothing in the application could be encrypted.
 *
 * Serving it here fixes that in the repository rather than in a server
 * configuration, which matters more than it sounds: an nginx `add_header` would
 * be invisible to CI, impossible to test, and gone the day this moves host. It
 * also means the single most security-critical asset in this codebase is no
 * longer the one file exempt from the middleware every other response goes
 * through.
 *
 * **Deliberately public.** The registration and login pages need the Worker
 * before anybody is authenticated, and the script is not a secret — it is the
 * same bundle every visitor's browser already runs, and it holds no key. What it
 * is not is *cheap*, so the route carries its own rate limit.
 */
class CryptoWorkerController extends Controller
{
    /**
     * The path the build writes to, outside `public/` on purpose.
     *
     * Kept as a constant rather than read from config: this is the contract
     * between vite.worker.config.ts and this controller, and a deployment where
     * those two disagree fails by serving a 404 for the Worker, which the
     * interface reports as "encryption unavailable".
     */
    public const PATH = 'app/private/worker/crypto.worker.js';

    public function __invoke(): BinaryFileResponse
    {
        $path = storage_path(self::PATH);

        if (! is_file($path)) {
            /*
             | A missing build, not a missing route. 404 is honest and the
             | client says what to do about it — `npm run build:worker` — but a
             | deployment that skipped the asset build is worth finding before a
             | user does, which is what tests/Feature/CryptoWorkerTest.php and
             | `vault:preflight` are for.
             */
            throw new NotFoundHttpException('The crypto worker has not been built.');
        }

        return response()->file($path, [
            'Content-Type' => 'text/javascript; charset=utf-8',

            /*
             | The header this whole controller exists for. Without it a
             | `require-corp` document cannot construct this Worker at all.
             */
            'Cross-Origin-Embedder-Policy' => 'require-corp',

            /*
             | Same-origin only, matching every other response here. The Worker
             | is same-origin with the page by necessity — `worker-src 'self'` —
             | so this costs nothing and closes the script to embedding
             | elsewhere.
             */
            'Cross-Origin-Resource-Policy' => 'same-origin',

            'X-Content-Type-Options' => 'nosniff',

            /*
             | Revalidated rather than cached hard. The Worker is fetched once
             | per page that unlocks, so the saving from a long max-age is small,
             | and the cost of a browser holding a stale copy of the one script
             | that touches key material is not. `response()->file()` sets
             | Last-Modified and answers a conditional request with a 304, so the
             | revalidation is a round trip and not a re-download.
             */
            'Cache-Control' => 'private, no-cache, max-age=0, must-revalidate',
        ]);
    }
}
