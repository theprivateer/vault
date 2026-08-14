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
            exclude: ['resources/js/**/*.test.ts', 'resources/js/app.ts'],
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
