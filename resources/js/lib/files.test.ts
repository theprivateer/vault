/**
 * Files end to end, with real cryptography and a fake network.
 *
 * The Worker is the genuine handler running in-process and the "server" is a
 * Map, so a round trip here exercises the whole path a real upload takes —
 * manifest, chunk keys, nonces, AADs — against a store that will hand back
 * whatever it is asked to. That is what makes the tamper cases meaningful:
 * the server in these tests is as dishonest as a compromised one, and the
 * client still refuses.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { DEFAULT_CHUNK_BYTES } from '@/crypto/chunks';
import { CryptoClient } from '@/crypto/worker/client';
import type { WorkerScope } from '@/crypto/worker/handler';
import { installHandler } from '@/crypto/worker/handler';
import type { Reply, Request } from '@/crypto/worker/protocol';
import { vaultKeyHandle } from '@/crypto/worker/protocol';

import { fromBase64 } from './bytes';
import {
    MAX_FILE_BYTES,
    downloadFile,
    isPreviewable,
    resumeUpload,
    uploadFile,
    withObjectUrl,
    type FileManifest,
} from './files';
import { HttpError } from './http';

const VAULT_UUID = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f7';
const LOCKBOX_UUID = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f8';

/** The same in-process Worker stand-in the client tests use. */
class FakeWorker {
    onmessage: ((event: MessageEvent<Reply>) => void) | null = null;

    onerror: ((event: unknown) => void) | null = null;

    private readonly scope: WorkerScope;

    constructor() {
        this.scope = {
            onmessage: null,
            postMessage: (reply: Reply) => {
                queueMicrotask(() => this.onmessage?.({ data: reply } as MessageEvent<Reply>));
            },
        };

        installHandler(this.scope);
    }

    postMessage(message: { id: number; request: Request }): void {
        this.scope.onmessage?.({ data: structuredClone(message) });
    }

    terminate(): void {}
}

/**
 * A server that stores what it is given and serves back whatever it is told to.
 *
 * Deliberately not a faithful implementation of the API. It records the
 * requests it received so the upload order can be asserted, and it exposes its
 * chunks so a test can reorder, drop or substitute them.
 */
class FakeServer {
    readonly rows = new Map<string, Record<string, unknown>>();

    readonly chunks = new Map<string, Uint8Array>();

    readonly calls: string[] = [];

    /** Chunks the server refuses to serve, by "uuid/index". */
    missing = new Set<string>();

    async handle(url: string, init?: RequestInit): Promise<Response> {
        const method = init?.method ?? 'GET';

        this.calls.push(`${method} ${url}`);

        const chunk = /^\/files\/([^/]+)\/chunks\/(\d+)$/.exec(url);

        if (method === 'POST') {
            const body = JSON.parse(init?.body as string) as Record<string, unknown>;

            this.rows.set(String(body.uuid), body);

            return this.ok({});
        }

        if (method === 'PUT' && chunk) {
            const bytes = new Uint8Array(await (init?.body as Blob).arrayBuffer());

            this.chunks.set(`${chunk[1]}/${chunk[2]}`, bytes);

            return this.ok({ stored: true });
        }

        if (method === 'GET' && chunk) {
            const key = `${chunk[1]}/${chunk[2]}`;
            const bytes = this.missing.has(key) ? undefined : this.chunks.get(key);

            if (!bytes) {
                return new Response(JSON.stringify({ message: 'Not found.' }), { status: 404 });
            }

            return new Response(bytes.slice(), { status: 200 });
        }

        if (method === 'GET' && url.endsWith('/status')) {
            const uuid = url.split('/')[2] ?? '';
            const row = this.rows.get(uuid) ?? {};
            const count = Number(row.chunk_count ?? 0);

            const missingChunks = Array.from({ length: count }, (_, index) => index).filter(
                (index) => !this.chunks.has(`${uuid}/${index}`),
            );

            return this.ok({ uuid, chunkCount: count, missingChunks, uploadedAt: null });
        }

        return new Response('{}', { status: 404 });
    }

    /** Swaps two stored chunks of a file, keeping both genuine. */
    swap(uuid: string, a: number, b: number): void {
        const first = this.chunks.get(`${uuid}/${a}`);
        const second = this.chunks.get(`${uuid}/${b}`);

        if (!first || !second) {
            throw new Error('cannot swap chunks that were never stored');
        }

        this.chunks.set(`${uuid}/${a}`, second);
        this.chunks.set(`${uuid}/${b}`, first);
    }

    private ok(body: unknown): Response {
        return new Response(JSON.stringify(body), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
        });
    }
}

let server: FakeServer;

beforeEach(() => {
    server = new FakeServer();

    vi.stubGlobal('document', { cookie: '' });
    vi.stubGlobal('fetch', (url: string, init?: RequestInit) => server.handle(url, init));
});

/** An unlocked client holding a Vault Key, which is all an upload needs. */
async function unlockedClient(): Promise<CryptoClient> {
    const client = new CryptoClient(() => new FakeWorker() as unknown as Worker);

    await client.generateInto(vaultKeyHandle(VAULT_UUID));

    return client;
}

function sourceFile(bytes: Uint8Array, name = 'invoice.pdf', type = 'application/pdf'): File {
    return new File([bytes.slice()], name, { type });
}

function pattern(length: number): Uint8Array {
    return Uint8Array.from({ length }, (_, index) => (index * 31 + 7) % 256);
}

/** The manifest, read back from the stored ciphertext the way a page would. */
async function readManifest(client: CryptoClient, uuid: string): Promise<FileManifest> {
    const { openItem } = await import('./items');
    const row = server.rows.get(uuid) ?? {};

    return openItem<FileManifest>(client, VAULT_UUID, 'file.payload', {
        uuid,
        payloadCt: String(row.payload_ct),
        wrappedItemKey: String(row.wrapped_item_key),
        payloadVersion: Number(row.payload_version),
    });
}

describe('uploading', function () {
    it('creates the row before it sends a single chunk', async () => {
        const client = await unlockedClient();

        const { uuid } = await uploadFile({
            client,
            vaultUuid: VAULT_UUID,
            lockboxUuid: LOCKBOX_UUID,
            file: sourceFile(pattern(2500)),
            chunkSize: 1000,
        });

        /*
         | Order, not just presence. The wrapped File Key lives on the row, and
         | a chunk that arrived before the row existed would have nowhere for
         | its key to be — which is also what would make a resumed upload
         | impossible.
         */
        expect(server.calls).toEqual([
            `POST /lockboxes/${LOCKBOX_UUID}/files`,
            `PUT /files/${uuid}/chunks/0`,
            `PUT /files/${uuid}/chunks/1`,
            `PUT /files/${uuid}/chunks/2`,
        ]);
    });

    it('puts the filename in the manifest and nothing else on the row', async () => {
        const client = await unlockedClient();

        const { uuid, manifest } = await uploadFile({
            client,
            vaultUuid: VAULT_UUID,
            lockboxUuid: LOCKBOX_UUID,
            file: sourceFile(pattern(100), 'salary — 2026.pdf'),
            chunkSize: 1000,
        });

        expect(manifest.filename).toBe('salary — 2026.pdf');

        // Everything the server was told, as one string. The name must not be
        // anywhere in it.
        expect(JSON.stringify(server.rows.get(uuid))).not.toContain('salary');
        expect(await readManifest(client, uuid)).toEqual(manifest);
    });

    it('reports progress once per chunk', async () => {
        const client = await unlockedClient();
        const seen: Array<[number, number]> = [];

        await uploadFile({
            client,
            vaultUuid: VAULT_UUID,
            lockboxUuid: LOCKBOX_UUID,
            file: sourceFile(pattern(2500)),
            chunkSize: 1000,
            onProgress: (done, total) => seen.push([done, total]),
        });

        expect(seen).toEqual([
            [1, 3],
            [2, 3],
            [3, 3],
        ]);
    });

    it('refuses a file past the ceiling before encrypting anything', async () => {
        const client = await unlockedClient();

        // A Blob reporting a size it does not hold, so the refusal is tested
        // without allocating a hundred mebibytes.
        const huge = Object.create(File.prototype) as File;
        Object.defineProperties(huge, {
            size: { value: MAX_FILE_BYTES + 1 },
            name: { value: 'enormous.iso' },
            type: { value: '' },
        });

        await expect(
            uploadFile({ client, vaultUuid: VAULT_UUID, lockboxUuid: LOCKBOX_UUID, file: huge }),
        ).rejects.toThrow(/MiB/);

        expect(server.calls).toEqual([]);
    });

    it('defaults to the configured chunk size', async () => {
        const client = await unlockedClient();

        const { manifest } = await uploadFile({
            client,
            vaultUuid: VAULT_UUID,
            lockboxUuid: LOCKBOX_UUID,
            file: sourceFile(pattern(10)),
        });

        expect(manifest.chunkSize).toBe(DEFAULT_CHUNK_BYTES);
        expect(manifest.chunkCount).toBe(1);
    });
});

describe('downloading', () => {
    async function round(bytes: Uint8Array, chunkSize = 1000) {
        const client = await unlockedClient();

        const { uuid, manifest } = await uploadFile({
            client,
            vaultUuid: VAULT_UUID,
            lockboxUuid: LOCKBOX_UUID,
            file: sourceFile(bytes),
            chunkSize,
        });

        return { client, uuid, manifest, wrappedItemKey: String(server.rows.get(uuid)?.wrapped_item_key) };
    }

    it.each([0, 1, 999, 1000, 1001, 5000])('returns a %i byte file byte for byte', async (size) => {
        const bytes = pattern(size);
        const { client, uuid, manifest, wrappedItemKey } = await round(bytes);

        const blob = await downloadFile({ client, vaultUuid: VAULT_UUID, uuid, manifest, wrappedItemKey });

        expect(new Uint8Array(await blob.arrayBuffer())).toEqual(bytes);
        expect(blob.type).toBe('application/pdf');
    });

    /*
     | Reordering, done by the server rather than in the cipher's own tests:
     | both chunks are genuine chunks of this file, correctly encrypted under
     | the right key. Only the index in the AAD tells them apart.
     */
    it('fails closed when the server swaps two chunks', async () => {
        const { client, uuid, manifest, wrappedItemKey } = await round(pattern(2500));

        server.swap(uuid, 0, 1);

        await expect(
            downloadFile({ client, vaultUuid: VAULT_UUID, uuid, manifest, wrappedItemKey }),
        ).rejects.toThrow(/Integrity check failed/);
    });

    /*
     | Truncation. The client asks for as many chunks as the *manifest* says,
     | so a server that simply stops serving the last one cannot make the file
     | look complete — it can only make the request fail.
     */
    it('fails when the server drops the final chunk', async () => {
        const { client, uuid, manifest, wrappedItemKey } = await round(pattern(2500));

        server.missing.add(`${uuid}/2`);

        await expect(
            downloadFile({ client, vaultUuid: VAULT_UUID, uuid, manifest, wrappedItemKey }),
        ).rejects.toThrow(HttpError);
    });

    /*
     | And the same attack dressed up: the server also shortens the count it
     | reports. It cannot, because the count the client loops on came out of
     | the encrypted manifest — but a client that took it from the row would
     | hand back a silently truncated file, so this pins where the number
     | comes from.
     */
    it('ignores a chunk count the server tries to shorten', async () => {
        const { client, uuid, manifest, wrappedItemKey } = await round(pattern(2500));

        server.rows.set(uuid, { ...server.rows.get(uuid), chunk_count: 2 });

        const blob = await downloadFile({ client, vaultUuid: VAULT_UUID, uuid, manifest, wrappedItemKey });

        expect(blob.size).toBe(2500);
    });

    it('fails closed when a chunk is replaced with one from another file', async () => {
        const first = await round(pattern(2500));
        const second = await round(pattern(2500));

        server.chunks.set(`${first.uuid}/1`, server.chunks.get(`${second.uuid}/1`)!);

        await expect(
            downloadFile({
                client: first.client,
                vaultUuid: VAULT_UUID,
                uuid: first.uuid,
                manifest: first.manifest,
                wrappedItemKey: first.wrappedItemKey,
            }),
        ).rejects.toThrow(/Integrity check failed/);
    });

    it('reports progress once per chunk', async () => {
        const { client, uuid, manifest, wrappedItemKey } = await round(pattern(2500));
        const seen: Array<[number, number]> = [];

        await downloadFile({
            client,
            vaultUuid: VAULT_UUID,
            uuid,
            manifest,
            wrappedItemKey,
            onProgress: (done, total) => seen.push([done, total]),
        });

        expect(seen).toEqual([
            [1, 3],
            [2, 3],
            [3, 3],
        ]);
    });

    /*
     | Redundant against the tags, and the one check that would catch a
     | reassembly bug on this side rather than an attack on the other.
     */
    it('rejects a file whose reassembled hash does not match the manifest', async () => {
        const { client, uuid, manifest, wrappedItemKey } = await round(pattern(2500));

        await expect(
            downloadFile({
                client,
                vaultUuid: VAULT_UUID,
                uuid,
                manifest: { ...manifest, sha256: '00'.repeat(32) },
                wrappedItemKey,
            }),
        ).rejects.toThrow(/Integrity check failed for file.content/);
    });
});

describe('resuming', () => {
    async function interrupted() {
        const client = await unlockedClient();
        const bytes = pattern(2500);

        const { uuid, manifest } = await uploadFile({
            client,
            vaultUuid: VAULT_UUID,
            lockboxUuid: LOCKBOX_UUID,
            file: sourceFile(bytes),
            chunkSize: 1000,
        });

        // As if the tab had closed after the first chunk.
        server.chunks.delete(`${uuid}/1`);
        server.chunks.delete(`${uuid}/2`);
        server.calls.length = 0;

        return {
            client,
            uuid,
            manifest,
            bytes,
            wrappedItemKey: String(server.rows.get(uuid)?.wrapped_item_key),
        };
    }

    it('sends only the chunks the server is missing', async () => {
        const { client, uuid, manifest, bytes, wrappedItemKey } = await interrupted();

        await resumeUpload({
            client,
            vaultUuid: VAULT_UUID,
            uuid,
            manifest,
            wrappedItemKey,
            file: sourceFile(bytes),
        });

        expect(server.calls).toEqual([
            `GET /files/${uuid}/status`,
            `PUT /files/${uuid}/chunks/1`,
            `PUT /files/${uuid}/chunks/2`,
        ]);

        const blob = await downloadFile({ client, vaultUuid: VAULT_UUID, uuid, manifest, wrappedItemKey });

        expect(new Uint8Array(await blob.arrayBuffer())).toEqual(bytes);
    });

    /*
     | The security check, not a convenience one. Resuming re-encrypts chunk i
     | with the nonce chunk i already used; if the bytes differ that is nonce
     | reuse under GCM, which leaks the XOR of the two plaintexts and the
     | authentication subkey with it.
     */
    it('refuses when the file has changed, before sending anything', async () => {
        const { client, uuid, manifest, bytes, wrappedItemKey } = await interrupted();

        const edited = Uint8Array.from(bytes);
        edited[42] = (edited[42] ?? 0) ^ 0xff;

        await expect(
            resumeUpload({
                client,
                vaultUuid: VAULT_UUID,
                uuid,
                manifest,
                wrappedItemKey,
                file: sourceFile(edited),
            }),
        ).rejects.toThrow(/re-use a nonce/);

        expect(server.calls).toEqual([]);
    });

    it('refuses a file of a different length without hashing it', async () => {
        const { client, uuid, manifest, wrappedItemKey } = await interrupted();

        await expect(
            resumeUpload({
                client,
                vaultUuid: VAULT_UUID,
                uuid,
                manifest,
                wrappedItemKey,
                file: sourceFile(pattern(2400)),
            }),
        ).rejects.toThrow(/different file/);

        expect(server.calls).toEqual([]);
    });
});

describe('previews', () => {
    it.each([
        ['image/png', true],
        ['image/jpeg', true],
        ['text/plain', true],
        ['image/svg+xml', false],
        ['application/pdf', false],
        ['text/html', false],
        ['', false],
    ])('treats %s as previewable: %s', (mime, expected) => {
        expect(isPreviewable({ mime } as FileManifest)).toBe(expected);
    });

    /*
     | An object URL is a live handle to decrypted content that anything on the
     | page can fetch, and one left behind outlives a lock. It has to be revoked
     | whether the caller succeeded or threw.
     */
    it('revokes the object url after use, and after a failure', async () => {
        const revoked: string[] = [];

        vi.stubGlobal('URL', {
            ...URL,
            createObjectURL: () => 'blob:fake',
            revokeObjectURL: (url: string) => revoked.push(url),
        });

        await withObjectUrl(new Blob(['x']), (url) => Promise.resolve(expect(url).toBe('blob:fake')));

        await expect(
            withObjectUrl(new Blob(['x']), () => Promise.reject(new Error('render failed'))),
        ).rejects.toThrow('render failed');

        expect(revoked).toEqual(['blob:fake', 'blob:fake']);
    });
});

describe('the manifest', () => {
    it('carries a nonce prefix that is fresh for every file', async () => {
        const client = await unlockedClient();

        const first = await uploadFile({
            client,
            vaultUuid: VAULT_UUID,
            lockboxUuid: LOCKBOX_UUID,
            file: sourceFile(pattern(10)),
        });

        const second = await uploadFile({
            client,
            vaultUuid: VAULT_UUID,
            lockboxUuid: LOCKBOX_UUID,
            file: sourceFile(pattern(10)),
        });

        /*
         | Two files with identical contents, so the only thing keeping their
         | nonces apart is the prefix. A shared prefix here would mean the same
         | (key, nonce) pair reused across files if a key were ever reused.
         */
        expect(first.manifest.noncePrefix).not.toBe(second.manifest.noncePrefix);
        expect(fromBase64(first.manifest.noncePrefix)).toHaveLength(8);
    });
});
