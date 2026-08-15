/**
 * Uploading and downloading encrypted file attachments.
 *
 * The layer above `crypto/chunks.ts`: it knows what a file *is* — a manifest
 * sealed like any other item payload, plus a sequence of chunks under a File Key
 * wrapped by the Vault Key — and it knows how to move one across the network
 * without ever handing the server anything it could read.
 *
 * **The manifest is the source of truth, not the response.** Chunk count, chunk
 * size and nonce prefix all live inside `payload_ct`, which means a client can
 * only learn them by decrypting. Every AAD built here uses those values. The
 * server also stores a chunk count, but only so it can bound an index and know
 * when an upload is finished; taking it from there when building an AAD would
 * be asking the sender to confirm its own claim, and would give back the
 * truncation attack the count exists to prevent (SR4).
 *
 * **Filenames never leave the browser.** The name, the MIME type and the hash
 * are manifest fields. The object in storage is keyed by a random UUID with no
 * extension, so the disk holds nothing that says what any of it is — which is
 * the direct answer to 2017, where `files.original_name`, `file_type` and
 * `extension` were plaintext columns.
 */
import type { ChunkAadParams } from '@/crypto/aad';
import { DEFAULT_CHUNK_BYTES, NONCE_PREFIX_LENGTH, chunkCountFor } from '@/crypto/chunks';
import { IntegrityError, InvalidParameterError } from '@/crypto/errors';
import { randomBytes } from '@/crypto/primitives';
import type { CryptoClient } from '@/crypto/worker/client';
import { vaultKeyHandle } from '@/crypto/worker/protocol';
import { sha256 } from '@noble/hashes/sha2.js';

import { fromBase64, toBase64, toHex } from './bytes';
import { getBinary, getJson, postJson, putBinary } from './http';
import { PAYLOAD_VERSION, sealItem, type EncryptedItem } from './items';
import { uuid7 } from './uuid';

/**
 * Key wrappings are bound at version 1, matching every other item key. See the
 * note on `KEY_WRAP_VERSION` in items.ts — a wrapped key has no schema to
 * evolve, so its binding must not move when the JSON beside it does.
 */
const KEY_WRAP_VERSION = 1;

/**
 * What is inside `payload_ct`.
 *
 * Everything identifying about a file is in here, including the two numbers the
 * chunk AADs are built from. `noncePrefix` lives here rather than in a column
 * for the same reason: the client that computes a nonce should be the only
 * party that has ever seen the ingredients.
 */
export interface FileManifest {
    filename: string;
    mime: string;
    /** SHA-256 of the plaintext, lowercase hex. Checked after reassembly. */
    sha256: string;
    chunkCount: number;
    chunkSize: number;
    plaintextSize: number;
    /** base64 of 8 random bytes. Public, but never served by the server. */
    noncePrefix: string;
    notes?: string;
}

/** The stored row, as the server describes it. */
export interface FileRecord extends EncryptedItem {
    lockboxUuid: string;
    /**
     * The server's own count. Used to render "12 of 40 uploaded" and nothing
     * else — never to build an AAD.
     */
    chunkCount: number;
    ciphertextSize: number;
    /** Null until every chunk has landed. An incomplete file is not readable. */
    uploadedAt: string | null;
    sortOrder: number;
    updatedAt: string | null;
}

/** What the status endpoint adds: which chunks the server is still missing. */
export interface FileStatus {
    uuid: string;
    chunkCount: number;
    missingChunks: number[];
    uploadedAt: string | null;
}

export type ProgressCallback = (done: number, total: number) => void;

export interface UploadOptions {
    client: CryptoClient;
    vaultUuid: string;
    lockboxUuid: string;
    file: File;
    /** Bytes per chunk. Recorded in the manifest, so it can change over time. */
    chunkSize?: number;
    onProgress?: ProgressCallback;
}

export interface UploadResult {
    uuid: string;
    manifest: FileManifest;
}

/**
 * The largest file this build will handle.
 *
 * Download reassembles into a `Blob`, and while the parts are themselves Blobs —
 * so the browser can keep them on disk rather than in the heap — the ceiling is
 * still real and still low enough to be worth refusing at the top rather than
 * discovering at chunk 900. Lifting it is the streaming-download stretch goal:
 * a Service Worker and a `TransformStream` turn reassembly into a pipe, and the
 * cap goes away with it.
 *
 * Mirrors `vault.files.max_bytes`, which is the copy that is actually enforced.
 * This one exists to fail early and say why.
 */
export const MAX_FILE_BYTES = 100 * 1024 * 1024;

function chunkAad(uuid: string, chunkIndex: number, chunkCount: number): ChunkAadParams {
    return { context: 'file.chunk', subject: uuid, version: PAYLOAD_VERSION, chunkIndex, chunkCount };
}

function keyAad(uuid: string) {
    return { context: 'item.key' as const, subject: uuid, version: KEY_WRAP_VERSION };
}

/** Reads one slice of a file into memory. Only one is held at a time. */
async function readChunk(file: Blob, index: number, chunkSize: number): Promise<Uint8Array> {
    const start = index * chunkSize;

    return new Uint8Array(await file.slice(start, start + chunkSize).arrayBuffer());
}

/**
 * Hashes the plaintext a chunk at a time.
 *
 * Streaming rather than `sha256(wholeFile)` because the whole point of chunking
 * is that the whole file is never resident. The hash goes into the manifest and
 * is checked again after a download completes.
 */
async function hashFile(file: Blob, chunkCount: number, chunkSize: number): Promise<string> {
    const hasher = sha256.create();

    for (let index = 0; index < chunkCount; index++) {
        hasher.update(await readChunk(file, index, chunkSize));
    }

    return toHex(hasher.digest());
}

/**
 * Encrypts a file and uploads it.
 *
 * The row is created *before* any chunk is sent, carrying the sealed manifest
 * and the wrapped File Key. That ordering is what makes a resumed upload
 * possible at all: the key survives in the row, so a transfer interrupted by a
 * closed tab can be picked up later instead of starting from a new key and
 * re-encrypting everything.
 *
 * Chunks go one at a time. A parallel window would fill the pipe better, and is
 * the obvious next thing to measure — but it also multiplies the resident
 * plaintext by the window size, and correctness of the ordering-and-resume
 * story was worth more here than throughput.
 */
export async function uploadFile({
    client,
    vaultUuid,
    lockboxUuid,
    file,
    chunkSize = DEFAULT_CHUNK_BYTES,
    onProgress,
}: UploadOptions): Promise<UploadResult> {
    if (file.size > MAX_FILE_BYTES) {
        throw new InvalidParameterError(
            `That file is ${Math.round(file.size / 1024 / 1024)} MiB. This build handles files up to ` +
                `${MAX_FILE_BYTES / 1024 / 1024} MiB, because a download is reassembled in the browser.`,
        );
    }

    const uuid = uuid7();
    const chunkCount = chunkCountFor(file.size, chunkSize);
    const noncePrefix = randomBytes(NONCE_PREFIX_LENGTH);

    const manifest: FileManifest = {
        filename: file.name,
        // Browsers report an empty type for anything they do not recognise, and
        // an empty Blob type is what the download path treats as "unknown".
        mime: file.type,
        sha256: await hashFile(file, chunkCount, chunkSize),
        chunkCount,
        chunkSize,
        plaintextSize: file.size,
        noncePrefix: toBase64(noncePrefix),
    };

    const sealed = await sealItem(client, vaultUuid, 'file.payload', uuid, manifest);

    await postJson(`/lockboxes/${lockboxUuid}/files`, {
        uuid,
        ...sealed,
        chunk_count: chunkCount,
        sort_order: 0,
    });

    await sendChunks({
        client,
        vaultUuid,
        uuid,
        file,
        manifest,
        wrappedItemKey: sealed.wrapped_item_key,
        indices: [...Array(chunkCount).keys()],
        onProgress,
    });

    return { uuid, manifest };
}

export interface ResumeOptions {
    client: CryptoClient;
    vaultUuid: string;
    /** The file row, already created, whose payload has already been opened. */
    uuid: string;
    manifest: FileManifest;
    wrappedItemKey: string;
    /** The same bytes as the interrupted upload. Verified before anything is sent. */
    file: File;
    onProgress?: ProgressCallback;
}

/**
 * Finishes an interrupted upload.
 *
 * **The hash check above is a security control, not a convenience.** Resuming
 * re-encrypts chunk *i* with the nonce chunk *i* already used. If the bytes were
 * the same, so is the ciphertext and nothing has happened. If they were
 * different, that is nonce reuse under AES-GCM, which leaks the XOR of the two
 * plaintexts and — far worse — the authentication subkey, letting an observer
 * forge chunks for the rest of the file. So a resume refuses unless the source
 * hashes to exactly what the manifest recorded. See crypto/chunks.ts.
 */
export async function resumeUpload({
    client,
    vaultUuid,
    uuid,
    manifest,
    wrappedItemKey,
    file,
    onProgress,
}: ResumeOptions): Promise<void> {
    if (file.size !== manifest.plaintextSize) {
        throw new InvalidParameterError(
            'That is a different file from the one this upload started with, so it cannot be resumed. ' +
                'Start a new upload instead.',
        );
    }

    const digest = await hashFile(file, manifest.chunkCount, manifest.chunkSize);

    if (digest !== manifest.sha256) {
        throw new InvalidParameterError(
            'The contents of that file have changed since the upload began, so it cannot be resumed — ' +
                'continuing would re-use a nonce, which is not safe. Start a new upload instead.',
        );
    }

    const status = await fetchStatus(uuid);

    await sendChunks({
        client,
        vaultUuid,
        uuid,
        file,
        manifest,
        wrappedItemKey,
        indices: status.missingChunks,
        onProgress,
    });
}

export function fetchStatus(uuid: string): Promise<FileStatus> {
    return getJson<FileStatus>(`/files/${uuid}/status`);
}

interface SendOptions {
    client: CryptoClient;
    vaultUuid: string;
    uuid: string;
    file: Blob;
    manifest: FileManifest;
    wrappedItemKey: string;
    indices: readonly number[];
    onProgress?: ProgressCallback | undefined;
}

async function sendChunks({
    client,
    vaultUuid,
    uuid,
    file,
    manifest,
    wrappedItemKey,
    indices,
    onProgress,
}: SendOptions): Promise<void> {
    const noncePrefix = fromBase64(manifest.noncePrefix);
    const wrapped = fromBase64(wrappedItemKey);
    let done = 0;

    for (const index of indices) {
        const plaintext = await readChunk(file, index, manifest.chunkSize);

        const sealed = await client.sealChunk({
            using: vaultKeyHandle(vaultUuid),
            wrapped,
            keyAad: keyAad(uuid),
            plaintext,
            noncePrefix,
            aad: chunkAad(uuid, index, manifest.chunkCount),
        });

        await putBinary(`/files/${uuid}/chunks/${index}`, sealed);

        done += 1;
        onProgress?.(done, indices.length);
    }
}

export interface DownloadOptions {
    client: CryptoClient;
    vaultUuid: string;
    uuid: string;
    manifest: FileManifest;
    wrappedItemKey: string;
    onProgress?: ProgressCallback;
}

/**
 * Fetches every chunk, decrypts it, and reassembles the plaintext.
 *
 * The loop is driven by `manifest.chunkCount`, which came out of the encrypted
 * payload. A server that serves fewer chunks than that cannot hide it — the
 * missing request fails — and one that serves a chunk from the wrong position or
 * the wrong file fails its tag, because the index, the count and the file's UUID
 * are all inside the AAD. **Nothing in this function compares lengths to detect
 * truncation; the cipher does it.**
 *
 * The parts are accumulated as `Blob`s rather than as `Uint8Array`s, so the
 * browser is free to spill them to disk instead of keeping the whole file in the
 * JavaScript heap. The SHA-256 is computed as the chunks arrive and checked at
 * the end — redundant against the tags, and worth the few milliseconds because
 * it is the one check that would catch a reassembly bug on this side.
 */
export async function downloadFile({
    client,
    vaultUuid,
    uuid,
    manifest,
    wrappedItemKey,
    onProgress,
}: DownloadOptions): Promise<Blob> {
    const noncePrefix = fromBase64(manifest.noncePrefix);
    const wrapped = fromBase64(wrappedItemKey);
    const hasher = sha256.create();
    const parts: Blob[] = [];

    for (let index = 0; index < manifest.chunkCount; index++) {
        const chunk = await getBinary(`/files/${uuid}/chunks/${index}`);

        const plaintext = await client.openChunk({
            using: vaultKeyHandle(vaultUuid),
            wrapped,
            keyAad: keyAad(uuid),
            chunk,
            noncePrefix,
            aad: chunkAad(uuid, index, manifest.chunkCount),
        });

        hasher.update(plaintext);
        parts.push(new Blob([plaintext.slice()]));

        onProgress?.(index + 1, manifest.chunkCount);
    }

    if (toHex(hasher.digest()) !== manifest.sha256) {
        throw new IntegrityError('file.content', uuid);
    }

    return new Blob(parts, { type: manifest.mime });
}

/** Types a preview can render inline without handing bytes to a plugin. */
const PREVIEWABLE = /^(image\/(png|jpeg|gif|webp|avif)|text\/plain)$/;

export function isPreviewable(manifest: FileManifest): boolean {
    return PREVIEWABLE.test(manifest.mime);
}

/**
 * Runs `use` against a temporary object URL, and revokes it however that ends.
 *
 * An object URL is a live handle to decrypted content that anything on the page
 * can fetch, and one left behind survives until the document is discarded — a
 * lock would wipe the store and terminate the Worker while the plaintext stayed
 * reachable at a `blob:` URL. Hence the `finally`, and hence callers being given
 * this rather than the URL itself.
 *
 * The caller must not retain the URL past the callback. For an `<img>`, that
 * means awaiting the load inside it.
 */
export async function withObjectUrl<T>(blob: Blob, use: (url: string) => Promise<T>): Promise<T> {
    const url = URL.createObjectURL(blob);

    try {
        return await use(url);
    } finally {
        URL.revokeObjectURL(url);
    }
}
