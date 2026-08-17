import { defineConfig } from 'vite';

/**
 * The crypto Worker is built separately, to a stable, unhashed, same-origin path
 * — and **outside `public/`**, so the application serves it rather than the web
 * server.
 *
 * Why not let the main build handle it: a Worker script must be same-origin with
 * the page. Under `npm run dev` Vite serves modules from its own port while
 * Laravel serves the page from another, so a Worker resolved through the dev
 * server cannot be constructed at all — the browser refuses before the CSP is
 * even consulted.
 *
 * Why not `public/`, which is where it lived until the first deployment: nginx
 * serves anything under `public/` directly, so the file arrived with no security
 * headers whatsoever. That is fatal rather than untidy — a document with
 * `Cross-Origin-Embedder-Policy: require-corp` may only create a dedicated
 * worker whose *own response* carries a compatible COEP, so the browser refused
 * to load it and the application could not encrypt anything. See docs/07 F13.
 *
 * Served by App\Http\Controllers\CryptoWorkerController, which is also the only
 * way to give the most security-critical asset here the same headers as every
 * other response. A header added to an nginx config instead would be invisible
 * to CI, untested, and lost on the next host.
 *
 * The cost is that the Worker is not hot-reloaded: after changing anything in
 * resources/js/crypto, run `npm run build:worker`. That is a fair trade for the
 * one part of the codebase that should never be swapped out invisibly.
 */
export default defineConfig({
    publicDir: false,
    build: {
        // Must not wipe anything else that builds into the same tree.
        emptyOutDir: false,
        outDir: 'storage/app/private/worker',
        target: 'es2022',
        rollupOptions: {
            input: 'resources/js/crypto/worker/crypto.worker.ts',
            output: {
                format: 'es',
                entryFileNames: 'crypto.worker.js',
                // Self-contained, so the Worker has no imports to resolve at
                // runtime and nothing else can be pulled into its scope.
                codeSplitting: false,
            },
        },
    },
});
