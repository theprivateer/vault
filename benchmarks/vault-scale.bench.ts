/**
 * The scale ceiling of "decrypt everything in the browser".
 *
 * Phase 4 asks a question it would be easy to answer with a shrug: how big can
 * a vault get before opening it in a browser stops being reasonable? Decision
 * D5 puts every name and note inside the ciphertext, so search cannot happen on
 * the server, so the client has to hold the lot. That is a defensible trade
 * only if somebody has measured what it costs. This is that measurement.
 *
 *   npm run bench:vault
 *
 * **What it measures.** Four things, at 100, 1,000 and 10,000 secrets:
 *
 *   1. Bulk decrypt through the real keyring, batched exactly as the app
 *      batches it, including a structuredClone per batch so the Worker
 *      boundary is charged rather than wished away.
 *   2. The same work one item at a time, as the pre-Phase-4 code did, so the
 *      batch has a number rather than a story.
 *   3. Building the search index over the decrypted plaintext.
 *   4. Search latency against that index.
 *
 * **What it does not measure.** The postMessage task hop — Node's event loop
 * is not the browser's — and rendering, which is Vue's problem rather than the
 * crypto's. The structured clone dominates the boundary cost and is included.
 * Node and a desktop browser are both V8, so this is a fair proxy for a laptop
 * and no proxy at all for a phone, exactly as ADR-0003 says of the Argon2id
 * numbers.
 *
 * Run through vitest rather than plain node because the modules under test are
 * TypeScript with bare specifiers, and adding a second build path for a
 * benchmark would be a strange thing to maintain.
 */
import { describe, expect, it } from 'vitest';

import { CryptoClient } from '@/crypto/worker/client';
import { installHandler, type WorkerScope } from '@/crypto/worker/handler';
import type { Reply, Request } from '@/crypto/worker/protocol';
import { vaultKeyHandle } from '@/crypto/worker/protocol';
import { fromBase64 } from '@/lib/bytes';
import { openAll } from '@/lib/decrypt';
import { PAYLOAD_VERSION, bulkOpenItem, parsePayload, sealItem, type SecretRecord } from '@/lib/items';
import { buildIndex, search, type Indexable } from '@/lib/search';

const SIZES = [100, 1_000, 10_000];

/** Runs the real handler in-process, cloning like a real postMessage. */
class FakeWorker {
    onmessage: ((event: MessageEvent<Reply>) => void) | null = null;

    onerror: ((event: unknown) => void) | null = null;

    /**
     * Requests sent across the boundary.
     *
     * Counted as well as timed because the timing understates the real thing.
     * This fake dispatches in-process; a real Worker is a separate thread and
     * every message is a task-queue round trip with a floor of its own. The
     * count is a hard fact about the protocol, and it is the honest half of the
     * batching argument.
     */
    crossings = 0;

    private readonly scope: WorkerScope;

    constructor() {
        this.scope = {
            onmessage: null,
            postMessage: (reply: Reply) => {
                queueMicrotask(() =>
                    this.onmessage?.({ data: structuredClone(reply) } as MessageEvent<Reply>),
                );
            },
        };

        installHandler(this.scope);
    }

    postMessage(message: { id: number; request: Request }): void {
        this.crossings++;
        this.scope.onmessage?.({ data: structuredClone(message) });
    }

    terminate(): void {}
}

const VAULT_UUID = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f7';
const LOCKBOX_UUID = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f9';

const uuidAt = (n: number) => `0192f3a1-4b2c-7d3e-8f90-${n.toString(16).padStart(12, '0')}`;

const SERVICES = ['aws', 'cloudflare', 'stripe', 'github', 'postgres', 'redis', 'sendgrid', 'datadog'];

/** A payload the size and shape of a real credential, not a toy. */
function payloadFor(n: number) {
    const service = SERVICES[n % SERVICES.length] ?? 'service';

    return {
        type: 'password' as const,
        key: `${service} ${n} production credential`,
        value: `pw-${n}-${'x'.repeat(24)}`,
        notes: `rotated on day ${n % 365}; owner team-${n % 12}; ticket OPS-${n}`,
        url: `https://${service}-${n}.example.com/login`,
    };
}

async function seed(client: CryptoClient, count: number): Promise<SecretRecord[]> {
    await client.generateInto(vaultKeyHandle(VAULT_UUID));

    const records: SecretRecord[] = [];

    for (let n = 0; n < count; n++) {
        const uuid = uuidAt(n);
        const sealed = await sealItem(client, VAULT_UUID, 'secret.payload', uuid, payloadFor(n));

        records.push({
            uuid,
            lockboxUuid: LOCKBOX_UUID,
            payloadCt: sealed.payload_ct,
            wrappedItemKey: sealed.wrapped_item_key,
            payloadVersion: PAYLOAD_VERSION,
            version: 1,
            sortOrder: n,
            linkedLockboxUuid: null,
            updatedAt: null,
        });
    }

    return records;
}

const ms = (value: number) => `${value.toFixed(0).padStart(6)} ms`;

async function time(work: () => Promise<void>): Promise<number> {
    const started = performance.now();

    await work();

    return performance.now() - started;
}

/**
 * Heap in use, after a collection if the runtime will give us one.
 *
 * Approximate by nature — V8 decides when to collect — so it is reported as an
 * order of magnitude rather than a precise figure, which is all anyone needs to
 * answer "will this fit in a tab".
 */
function heapMiB(): number {
    globalThis.gc?.();

    return process.memoryUsage().heapUsed / 1024 / 1024;
}

describe('vault scale', () => {
    it(
        'measures decrypt, index and search across three orders of magnitude',
        // Ten thousand seals plus a serial comparison run: minutes, not seconds.
        { timeout: 15 * 60 * 1000 },
        async () => {
            const rows: string[] = [];

            for (const size of SIZES) {
                const worker = new FakeWorker();
                const client = new CryptoClient(() => worker as unknown as Worker);
                const records = await seed(client, size);

                const storedBytes = records.reduce(
                    (total, record) => total + fromBase64(record.payloadCt).length,
                    0,
                );

                const before = heapMiB();
                const crossingsBefore = worker.crossings;

                let opened: Array<{ payload: ReturnType<typeof payloadFor> | null }> = [];

                const batched = await time(async () => {
                    opened = await openAll(
                        client,
                        VAULT_UUID,
                        'secret.payload',
                        records,
                        () => 'This secret',
                    );
                });

                expect(opened).toHaveLength(size);
                expect(opened.every((entry) => entry.payload !== null)).toBe(true);

                const afterDecrypt = heapMiB();
                const batchedCrossings = worker.crossings - crossingsBefore;

                /*
                 | The pre-Phase-4 path: one request per item. Sampled at the
                 | largest size, because the per-item cost is what is being
                 | compared and running it in full would dominate the run.
                 |
                 | Its *timing* here is a floor rather than a fair comparison —
                 | this fake dispatches in-process, where a real Worker is a
                 | separate thread with a per-message cost this cannot model.
                 | The crossing count beside it is the fact that does not
                 | depend on the model.
                 */
                const sampled = records.slice(0, Math.min(size, 1_000));
                const serialBefore = worker.crossings;

                const serial = await time(async () => {
                    for (const record of sampled) {
                        const [result] = await client.openMany([
                            bulkOpenItem(VAULT_UUID, 'secret.payload', record),
                        ]);

                        if (result?.ok) {
                            parsePayload(result.bytes, record.payloadVersion);
                        }
                    }
                });

                const perItemSerial = serial / sampled.length;
                const serialCrossings = ((worker.crossings - serialBefore) / sampled.length) * size;

                const documents: Indexable[] = records.map((record, n) => ({
                    id: record.uuid,
                    fields: {
                        name: payloadFor(n).key,
                        notes: payloadFor(n).notes,
                        url: payloadFor(n).url,
                        type: 'password',
                    },
                }));

                let index = buildIndex([]);
                const indexing = await time(async () => {
                    index = buildIndex(documents);
                });

                const afterIndex = heapMiB();

                // Three shapes of query: a common prefix that matches many, a
                // narrowing pair, and a miss. The worst of them is the number
                // that matters for typing latency.
                const queries = ['aws', 'aws prod', 'stripe 42', 'zzzz'];
                const runs = 50;

                const searching = await time(async () => {
                    for (let run = 0; run < runs; run++) {
                        for (const query of queries) {
                            search(index, query);
                        }
                    }
                });

                const perQuery = searching / (runs * queries.length);

                rows.push(
                    [
                        String(size).padStart(6),
                        ms(batched),
                        ms(perItemSerial * size),
                        String(batchedCrossings).padStart(9),
                        String(Math.round(serialCrossings)).padStart(9),
                        ms(indexing),
                        `${perQuery.toFixed(3).padStart(6)} ms`,
                        `${(storedBytes / 1024 / 1024).toFixed(1).padStart(5)} MiB`,
                        `${(afterDecrypt - before).toFixed(0).padStart(5)} MiB`,
                        `${(afterIndex - afterDecrypt).toFixed(0).padStart(5)} MiB`,
                    ].join('  '),
                );

                client.terminate();
            }

            const header = [
                ' items'.padStart(6),
                'batched'.padStart(9),
                'serial'.padStart(9),
                'batch msg'.padStart(9),
                'serial msg'.padStart(9),
                'index'.padStart(9),
                'per query'.padStart(9),
                'stored'.padStart(9),
                'heap'.padStart(9),
                'idx heap'.padStart(9),
            ].join('  ');

            // A benchmark that cannot print its results is not a benchmark.
            console.log(`\nnode ${process.version}\n\n${header}\n${rows.join('\n')}\n`);
        },
    );
});
