import { defineConfig } from 'vite';

/**
 * The crypto Worker is built separately, to a stable, unhashed, same-origin path.
 *
 * Why not let the main build handle it: a Worker script must be same-origin
 * with the page. Under `npm run dev` Vite serves modules from its own port
 * while Laravel serves the page from another, so a Worker resolved through the
 * dev server cannot be constructed at all — the browser refuses before the CSP
 * is even consulted.
 *
 * Building it to `/build/crypto.worker.js` makes development and production
 * behave identically, and keeps `worker-src 'self'` intact in both. The cost is
 * that the Worker is not hot-reloaded: after changing anything in
 * resources/js/crypto, run `npm run build:worker`. That is a fair trade for the
 * one part of the codebase that should never be swapped out invisibly.
 */
export default defineConfig({
    // The output directory sits inside publicDir; nothing needs copying.
    publicDir: false,
    build: {
        // Must not wipe the main build's output.
        emptyOutDir: false,
        outDir: 'public/build',
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
