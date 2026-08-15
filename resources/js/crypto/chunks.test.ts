import { describe, expect, it, vi } from 'vitest';

import type { ChunkAadParams } from './aad';
import {
    ALG_AES_256_GCM,
    CHUNK_NONCE_LENGTH,
    DEFAULT_CHUNK_BYTES,
    GCM_TAG_LENGTH,
    MIN_CHUNK_LENGTH,
    NONCE_PREFIX_LENGTH,
    chunkCountFor,
    chunkNonce,
    openChunk,
    sealChunk,
} from './chunks';
import { ENVELOPE_VERSION } from './envelope';
import {
    IntegrityError,
    InvalidParameterError,
    MalformedEnvelopeError,
    UnsupportedEnvelopeError,
} from './errors';
import { KEY_LENGTH, randomBytes } from './primitives';

const FILE = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f6';
const OTHER_FILE = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f7';

const key = () => randomBytes(KEY_LENGTH);
const prefix = () => randomBytes(NONCE_PREFIX_LENGTH);

function aad(chunkIndex: number, chunkCount: number, subject = FILE): ChunkAadParams {
    return { context: 'file.chunk', subject, version: 2, chunkIndex, chunkCount };
}

describe('round trip', () => {
    it.each([0, 1, 15, 16, 4096, 60_000])('survives a %i byte chunk', async (size) => {
        const k = key();
        const p = prefix();
        const plaintext = randomBytes(Math.max(size, 1)).subarray(0, size);

        const chunk = await sealChunk(k, plaintext, p, aad(0, 1));

        expect(await openChunk(k, chunk, p, aad(0, 1))).toEqual(plaintext);
    });

    it('carries the version and algorithm in its first two bytes', async () => {
        const chunk = await sealChunk(key(), new Uint8Array(8), prefix(), aad(0, 1));

        expect(chunk[0]).toBe(ENVELOPE_VERSION);
        expect(chunk[1]).toBe(ALG_AES_256_GCM);
    });

    it('costs a header and a tag over the plaintext, and no nonce', async () => {
        const chunk = await sealChunk(key(), new Uint8Array(1000), prefix(), aad(0, 1));

        // The nonce is derived rather than stored, so it is not on the wire.
        expect(chunk).toHaveLength(2 + 1000 + GCM_TAG_LENGTH);
        expect(await sealChunk(key(), new Uint8Array(0), prefix(), aad(0, 1))).toHaveLength(MIN_CHUNK_LENGTH);
    });

    /*
     | The chunk is normally a view over a larger read buffer. Handing WebCrypto
     | the underlying buffer instead of the view is a silent wrong-data bug, so
     | it is worth an explicit case rather than trusting the copy in toBuffer.
     */
    it('encrypts the view it was given, not the buffer behind it', async () => {
        const k = key();
        const p = prefix();
        const backing = randomBytes(300);
        const view = backing.subarray(100, 200);

        const chunk = await sealChunk(k, view, p, aad(0, 1));

        expect(await openChunk(k, chunk, p, aad(0, 1))).toEqual(view);
    });
});

/**
 * The four attacks the per-chunk binding exists to stop. Each one is a thing a
 * malicious server can do with nothing but the ciphertext it already holds.
 */
describe('tamper detection', () => {
    it('fails closed when a chunk is replayed at a different index', async () => {
        const k = key();
        const p = prefix();

        const chunk = await sealChunk(k, randomBytes(64), p, aad(3, 10));

        await expect(openChunk(k, chunk, p, aad(4, 10))).rejects.toThrow(IntegrityError);
    });

    /*
     | Truncation. An attacker drops the final chunk and tells the client the
     | file is one chunk shorter than it is. Without the count in the AAD every
     | remaining chunk would still verify and the client would hand back a
     | plausible, silently shortened file.
     */
    it('fails closed when the chunk count is reduced', async () => {
        const k = key();
        const p = prefix();

        const chunk = await sealChunk(k, randomBytes(64), p, aad(0, 40));

        await expect(openChunk(k, chunk, p, aad(0, 39))).rejects.toThrow(IntegrityError);
    });

    /*
     | Reordering. Two chunks of the same file swapped over — each one is a
     | genuine chunk of the file, correctly encrypted, so only the index binding
     | can tell them apart.
     */
    it('fails closed when two chunks are swapped', async () => {
        const k = key();
        const p = prefix();

        const first = await sealChunk(k, randomBytes(64), p, aad(0, 2));
        const second = await sealChunk(k, randomBytes(64), p, aad(1, 2));

        await expect(openChunk(k, second, p, aad(0, 2))).rejects.toThrow(IntegrityError);
        await expect(openChunk(k, first, p, aad(1, 2))).rejects.toThrow(IntegrityError);
    });

    /*
     | Cross-file replay. Even under one vault key, a chunk of one file cannot
     | be served as a chunk of another: the file's own UUID is in the AAD.
     */
    it('fails closed when a chunk is replayed from another file', async () => {
        const k = key();
        const p = prefix();

        const chunk = await sealChunk(k, randomBytes(64), p, aad(0, 1, FILE));

        await expect(openChunk(k, chunk, p, aad(0, 1, OTHER_FILE))).rejects.toThrow(IntegrityError);
    });

    it('fails closed on a flipped bit anywhere in the body', async () => {
        const k = key();
        const p = prefix();
        const chunk = await sealChunk(k, randomBytes(64), p, aad(0, 1));

        for (const at of [2, 20, chunk.length - 1]) {
            const damaged = Uint8Array.from(chunk);
            damaged[at] = (damaged[at] ?? 0) ^ 0x01;

            await expect(openChunk(k, damaged, p, aad(0, 1))).rejects.toThrow(IntegrityError);
        }
    });

    it('fails closed under the wrong key, and under the wrong nonce prefix', async () => {
        const k = key();
        const p = prefix();
        const chunk = await sealChunk(k, randomBytes(64), p, aad(0, 1));

        await expect(openChunk(key(), chunk, p, aad(0, 1))).rejects.toThrow(IntegrityError);
        await expect(openChunk(k, chunk, prefix(), aad(0, 1))).rejects.toThrow(IntegrityError);
    });
});

describe('malformed input', () => {
    it.each([0, 1, MIN_CHUNK_LENGTH - 1])('rejects a %i byte chunk as too short', async (length) => {
        await expect(openChunk(key(), new Uint8Array(length), prefix(), aad(0, 1))).rejects.toThrow(
            MalformedEnvelopeError,
        );
    });

    it('refuses an unknown version or algorithm rather than guessing', async () => {
        const k = key();
        const p = prefix();
        const chunk = await sealChunk(k, randomBytes(32), p, aad(0, 1));

        const wrongVersion = Uint8Array.from(chunk);
        wrongVersion[0] = 9;

        const wrongAlgorithm = Uint8Array.from(chunk);
        // 1 is XChaCha20-Poly1305: a real algorithm, and still not this one.
        wrongAlgorithm[1] = 1;

        await expect(openChunk(k, wrongVersion, p, aad(0, 1))).rejects.toThrow(UnsupportedEnvelopeError);
        await expect(openChunk(k, wrongAlgorithm, p, aad(0, 1))).rejects.toThrow(UnsupportedEnvelopeError);
    });

    it.each([16, 31, 33])('rejects a %i byte key', async (length) => {
        await expect(
            sealChunk(new Uint8Array(length), new Uint8Array(8), prefix(), aad(0, 1)),
        ).rejects.toThrow(InvalidParameterError);

        // A well-formed header, so this reaches the key check rather than
        // being turned away as an unrecognised algorithm first.
        const shaped = new Uint8Array(MIN_CHUNK_LENGTH + 8);
        shaped[0] = ENVELOPE_VERSION;
        shaped[1] = ALG_AES_256_GCM;

        await expect(openChunk(new Uint8Array(length), shaped, prefix(), aad(0, 1))).rejects.toThrow(
            InvalidParameterError,
        );
    });

    it('reports a missing SubtleCrypto as an environment problem', async () => {
        const k = key();
        const p = prefix();
        const original = globalThis.crypto;

        // A page on an insecure origin has crypto.getRandomValues but no
        // subtle, and a file upload that silently did nothing would be worse
        // than one that says why.
        vi.spyOn(globalThis, 'crypto', 'get').mockReturnValue({
            getRandomValues: original.getRandomValues.bind(original),
            subtle: undefined,
        } as unknown as Crypto);

        try {
            await expect(sealChunk(k, new Uint8Array(8), p, aad(0, 1))).rejects.toThrow(/secure context/);
        } finally {
            vi.restoreAllMocks();
        }
    });
});

describe('nonces', () => {
    it('is the prefix followed by the index, big-endian', () => {
        const p = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);

        expect(chunkNonce(p, 0)).toEqual(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0]));
        expect(chunkNonce(p, 258)).toEqual(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 1, 2]));
        expect(chunkNonce(p, 0xffffffff)).toHaveLength(CHUNK_NONCE_LENGTH);
    });

    /*
     | The property the whole construction exists for. AES-GCM's nonce is too
     | short to generate randomly per chunk, so it is counted instead — and a
     | repeat within one file must be impossible rather than unlikely.
     */
    it('never repeats within a file', () => {
        const p = prefix();
        const seen = new Set(Array.from({ length: 5000 }, (_, i) => chunkNonce(p, i).toString()));

        expect(seen.size).toBe(5000);
    });

    it.each([-1, 1.5, 0x100000000, Number.NaN])('rejects the index %p', (index) => {
        expect(() => chunkNonce(prefix(), index)).toThrow(InvalidParameterError);
    });

    it.each([0, 7, 9, 12])('rejects a %i byte prefix', (length) => {
        expect(() => chunkNonce(new Uint8Array(length), 0)).toThrow(InvalidParameterError);
    });
});

describe('chunk counts', () => {
    it.each([
        [0, 1],
        [1, 1],
        [DEFAULT_CHUNK_BYTES, 1],
        [DEFAULT_CHUNK_BYTES + 1, 2],
        [DEFAULT_CHUNK_BYTES * 3, 3],
    ])('splits %i bytes into %i chunks', (size, expected) => {
        expect(chunkCountFor(size, DEFAULT_CHUNK_BYTES)).toBe(expected);
    });

    /*
     | An empty file is one empty chunk, not zero. A file with no chunks would
     | have nothing authenticated at all, so its length could be changed from
     | zero to anything without a tag ever failing.
     */
    it('gives an empty file one chunk', () => {
        expect(chunkCountFor(0, DEFAULT_CHUNK_BYTES)).toBe(1);
    });

    it.each([-1, 1.5, Number.NaN])('rejects the size %p', (size) => {
        expect(() => chunkCountFor(size, DEFAULT_CHUNK_BYTES)).toThrow(InvalidParameterError);
    });

    it.each([0, -1, 1.5])('rejects the chunk size %p', (chunkSize) => {
        expect(() => chunkCountFor(100, chunkSize)).toThrow(InvalidParameterError);
    });
});
