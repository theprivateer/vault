import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';

export default defineConfig({
    resolve: {
        alias: {
            '@': fileURLToPath(new URL('./resources/js', import.meta.url)),
        },
    },
    test: {
        include: ['resources/js/**/*.test.ts'],
        environment: 'node',
        coverage: {
            provider: 'v8',
            reporter: ['text', 'html', 'lcov'],
            include: ['resources/js/**/*.ts'],
            exclude: [
                'resources/js/**/*.test.ts',
                'resources/js/app.ts',
                /*
                 | The Worker entry point is a single call to installHandler,
                 | which cannot execute outside a real Worker scope. The handler
                 | logic it installs is fully tested against a fake scope — the
                 | code is split this way so that exactly one line is untestable
                 | rather than the whole Worker.
                 */
                'resources/js/crypto/worker/crypto.worker.ts',
            ],
            /*
             | Total coverage is noise; coverage of the crypto core is not.
             | Phase 1 builds resources/js/crypto and this threshold is what
             | keeps it at 100%. See docs/06-testing-and-ci.md.
             */
            thresholds: {
                'resources/js/crypto/**/*.ts': {
                    statements: 100,
                    branches: 100,
                    functions: 100,
                    lines: 100,
                },
            },
        },
    },
});
