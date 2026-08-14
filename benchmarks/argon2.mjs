/**
 * Argon2id benchmark for ADR-0003.
 *
 * The password KDF runs in the browser on every unlock, so its cost is a UX
 * budget as much as a security parameter. This measures the pure-JS
 * implementation against the budget in docs/adr/0003-argon2id-implementation.md:
 * under 2s on a modern laptop, under 5s on a mid-range phone.
 *
 *   npm run bench:argon2
 *
 * Node is a fair proxy for a desktop browser (both V8). Phone numbers need a
 * real device — see the browser harness note in the ADR.
 */
import { argon2id } from '@noble/hashes/argon2.js';
import os from 'node:os';

const PASSWORD = 'correct horse battery staple';
const SALT = new Uint8Array(16).fill(7);
const RUNS = 5;

const configs = [
    { label: 'spec: m=64MiB t=3 p=1', m: 64 * 1024, t: 3, p: 1 },
    { label: 'm=64MiB t=2 p=1', m: 64 * 1024, t: 2, p: 1 },
    { label: 'm=32MiB t=3 p=1', m: 32 * 1024, t: 3, p: 1 },
    { label: 'OWASP min: m=19MiB t=2 p=1', m: 19 * 1024, t: 2, p: 1 },
];

console.log(`${os.cpus()[0].model} · ${os.cpus().length} cores · node ${process.version}\n`);

for (const { label, m, t, p } of configs) {
    // Warm up so JIT compilation is not charged to the first configuration.
    argon2id(PASSWORD, SALT, { m, t, p, dkLen: 64 });

    const times = [];
    for (let i = 0; i < RUNS; i++) {
        const start = performance.now();
        argon2id(PASSWORD, SALT, { m, t, p, dkLen: 64 });
        times.push(performance.now() - start);
    }

    const mean = times.reduce((a, b) => a + b, 0) / times.length;

    console.log(
        `${label.padEnd(28)} mean ${mean.toFixed(0).padStart(6)} ms` +
            `   min ${Math.min(...times)
                .toFixed(0)
                .padStart(6)} ms` +
            `   max ${Math.max(...times)
                .toFixed(0)
                .padStart(6)} ms`,
    );
}
