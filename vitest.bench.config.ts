import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';

/**
 * The benchmarks, kept out of the test run.
 *
 * They seal and open ten thousand records and take minutes, which is fine for
 * something run deliberately and intolerable in a pre-commit loop. Same
 * aliases as the test config so the benchmark exercises the real modules
 * rather than a copy of them.
 */
export default defineConfig({
    resolve: {
        alias: {
            '@': fileURLToPath(new URL('./resources/js', import.meta.url)),
        },
    },
    test: {
        include: ['benchmarks/**/*.bench.ts'],
        environment: 'node',
        // One at a time: a benchmark sharing a core with another benchmark is
        // measuring the scheduler.
        fileParallelism: false,
        // --expose-gc so the heap figures are taken after a collection. Without
        // it they are whatever V8 has not got round to freeing, which is noise
        // with a plausible-looking number attached.
        execArgv: ['--expose-gc'],
    },
});
