/**
 * Chunked file encryption.
 *
 *   ┌────────┬────────┬────────────────────────┐
 *   │ ver    │ alg    │ ciphertext ‖ tag       │
 *   │ 1 byte │ 1 byte │ variable + 16 bytes    │
 *   └────────┴────────┴────────────────────────┘
 *
 * **The nonce is not in the chunk.** Every other ciphertext in this codebase
 * carries its own random nonce, because a 192-bit XChaCha20 nonce is safe to
 * generate that way. AES-GCM's is 96 bits, which is not: at a few billion
 * chunks the birthday bound starts to matter, and a repeated nonce under one key
 * is a total break of GCM rather than a degradation. So the nonce is
 * *constructed* — an 8-byte random prefix chosen once per file, followed by the
 * chunk index as a 4-byte big-endian counter — which makes a repeat within a
 * file impossible rather than merely unlikely.
 *
 * Deriving it also means there is no nonce field for a server to swap, and it
 * removes 12 bytes per chunk from the wire. The prefix lives in the file's
 * encrypted manifest, so the client that computes the nonce is the only party
 * that ever knew it.
 *
 * **Why AES-GCM here and XChaCha20-Poly1305 everywhere else.** Every browser
 * this targets implements AES-GCM in hardware through WebCrypto, and a 100 MiB
 * upload is the one place in the application where the difference between a
 * hardware cipher and a very good JavaScript one is the difference between a
 * progress bar and a hung tab. Payloads are kilobytes and stay on the audited
 * pure-TS path; file bodies are the exception, and the exception is confined to
 * this file.
 *
 * **The one rule a caller must not break.** A given (file key, chunk index) pair
 * must never be used to encrypt two different plaintexts — that is nonce reuse,
 * and under GCM it leaks the XOR of the plaintexts *and* the authentication
 * subkey. Re-uploading the same bytes of the same file at the same index is
 * fine and is what makes a resumed upload work; uploading *different* bytes into
 * an existing file row is not, which is why `lib/files.ts` verifies the source
 * against the manifest's hash before it resumes.
 *
 * Spec: docs/03-cryptographic-design.md#files
 */
import type { ChunkAadParams } from './aad';
import { buildChunkAad } from './aad';
import {
    IntegrityError,
    InvalidParameterError,
    MalformedEnvelopeError,
    UnsupportedEnvelopeError,
} from './errors';
import { KEY_LENGTH } from './primitives';
import { ENVELOPE_VERSION } from './envelope';

/** AES-256-GCM. Distinct from ALG_XCHACHA20_POLY1305 (1) in envelope.ts. */
export const ALG_AES_256_GCM = 2;

/** Random, per file, and never reused across two files. */
export const NONCE_PREFIX_LENGTH = 8;

/** The counter half of the nonce. 4 bytes caps a file at 2^32 chunks. */
const COUNTER_LENGTH = 4;

export const CHUNK_NONCE_LENGTH = NONCE_PREFIX_LENGTH + COUNTER_LENGTH;

/** GCM tag, in bytes. WebCrypto wants it in bits. */
export const GCM_TAG_LENGTH = 16;

const HEADER_LENGTH = 2;

/** An empty chunk still costs a header and a tag. */
export const MIN_CHUNK_LENGTH = HEADER_LENGTH + GCM_TAG_LENGTH;

/**
 * 1 MiB.
 *
 * Small enough that a failed chunk is a cheap retry and that the plaintext of
 * one chunk is a comfortable allocation; large enough that a 100 MiB file is a
 * hundred requests rather than a hundred thousand. It is recorded in the
 * manifest rather than assumed, so changing it does not strand existing files.
 */
export const DEFAULT_CHUNK_BYTES = 1024 * 1024;

/**
 * How many chunks a plaintext of this size takes.
 *
 * A zero-length file is one empty chunk, not zero chunks: a file with no chunks
 * would have nothing to authenticate, so its length could be changed from 0 to
 * anything without a tag ever failing.
 */
export function chunkCountFor(plaintextSize: number, chunkSize: number): number {
    if (!Number.isSafeInteger(plaintextSize) || plaintextSize < 0) {
        throw new InvalidParameterError(`A file cannot be ${plaintextSize} bytes.`);
    }

    if (!Number.isSafeInteger(chunkSize) || chunkSize < 1) {
        throw new InvalidParameterError(`Chunk size must be at least one byte, received: ${chunkSize}`);
    }

    return Math.max(1, Math.ceil(plaintextSize / chunkSize));
}

/**
 * Builds the nonce for one chunk: prefix ‖ big-endian index.
 *
 * Big-endian for no reason beyond convention — it is never compared as a number
 * — but it is fixed here rather than at the call sites so that both ends of a
 * round trip cannot disagree about it.
 */
export function chunkNonce(noncePrefix: Uint8Array, chunkIndex: number): Uint8Array {
    if (noncePrefix.length !== NONCE_PREFIX_LENGTH) {
        throw new InvalidParameterError(
            `A nonce prefix must be ${NONCE_PREFIX_LENGTH} bytes, received ${noncePrefix.length}.`,
        );
    }

    if (!Number.isSafeInteger(chunkIndex) || chunkIndex < 0 || chunkIndex > 0xffffffff) {
        throw new InvalidParameterError(`Chunk index ${chunkIndex} does not fit a 32-bit counter.`);
    }

    const nonce = new Uint8Array(CHUNK_NONCE_LENGTH);

    nonce.set(noncePrefix, 0);
    new DataView(nonce.buffer).setUint32(NONCE_PREFIX_LENGTH, chunkIndex, false);

    return nonce;
}

/**
 * The WebCrypto surface this module needs, named so a test can supply its own.
 *
 * Node and every target browser provide `globalThis.crypto.subtle`, but an
 * insecure origin does not — and a file upload silently doing nothing because
 * the page was served over plain HTTP is worth a message that says so.
 */
function subtle(): SubtleCrypto {
    const available: SubtleCrypto | undefined = globalThis.crypto?.subtle;

    if (!available) {
        throw new InvalidParameterError(
            'WebCrypto is unavailable, so files cannot be encrypted. This usually means the page ' +
                'was served from an insecure origin — SubtleCrypto is only exposed in a secure context.',
        );
    }

    return available;
}

async function importKey(key: Uint8Array, usage: KeyUsage): Promise<CryptoKey> {
    if (key.length !== KEY_LENGTH) {
        throw new InvalidParameterError(`Key must be ${KEY_LENGTH} bytes, received ${key.length}.`);
    }

    /*
     | Non-extractable: once imported, the bytes cannot be read back out through
     | this handle. The originals still exist in the keyring, so this is a small
     | hardening rather than a guarantee — but it costs nothing.
     */
    return subtle().importKey('raw', toBuffer(key), 'AES-GCM', false, [usage]);
}

/**
 * Copies into a standalone ArrayBuffer.
 *
 * A `Uint8Array` that arrived as a view over a larger buffer — a chunk sliced
 * out of a read buffer, which is the normal case here — would otherwise hand
 * WebCrypto the *whole* buffer, since `.buffer` ignores byteOffset and length.
 * That is a silent wrong-data bug rather than an error, so the copy is not
 * optional.
 */
function toBuffer(bytes: Uint8Array): ArrayBuffer {
    return bytes.slice().buffer;
}

/**
 * Encrypts one chunk, bound to its file, its index and the file's chunk count.
 *
 * `aad` is required and has no default, exactly as in `seal()`: an unbound
 * chunk is a chunk that can be moved between files or reordered within one.
 */
export async function sealChunk(
    key: Uint8Array,
    plaintext: Uint8Array,
    noncePrefix: Uint8Array,
    aad: ChunkAadParams,
): Promise<Uint8Array> {
    const nonce = chunkNonce(noncePrefix, aad.chunkIndex);
    const cryptoKey = await importKey(key, 'encrypt');

    const body = new Uint8Array(
        await subtle().encrypt(
            {
                name: 'AES-GCM',
                iv: toBuffer(nonce),
                additionalData: toBuffer(buildChunkAad(aad)),
                tagLength: GCM_TAG_LENGTH * 8,
            },
            cryptoKey,
            toBuffer(plaintext),
        ),
    );

    const chunk = new Uint8Array(HEADER_LENGTH + body.length);

    chunk[0] = ENVELOPE_VERSION;
    chunk[1] = ALG_AES_256_GCM;
    chunk.set(body, HEADER_LENGTH);

    return chunk;
}

/**
 * Decrypts one chunk.
 *
 * Throws on every failure path, like `open()`. A chunk that came back from the
 * wrong file, from the wrong position in the right file, or from a file whose
 * length has been changed all fail here as an `IntegrityError` — the tag check
 * is what detects reordering and truncation, rather than a length comparison
 * somewhere in the application that might not run.
 */
export async function openChunk(
    key: Uint8Array,
    chunk: Uint8Array,
    noncePrefix: Uint8Array,
    aad: ChunkAadParams,
): Promise<Uint8Array> {
    if (chunk.length < MIN_CHUNK_LENGTH) {
        throw new MalformedEnvelopeError(`Chunk is ${chunk.length} bytes, minimum is ${MIN_CHUNK_LENGTH}.`);
    }

    // Both indices are in range: the length check above guarantees a header.
    const version = chunk[0]!;
    const algorithm = chunk[1]!;

    if (version !== ENVELOPE_VERSION || algorithm !== ALG_AES_256_GCM) {
        throw new UnsupportedEnvelopeError(version, algorithm);
    }

    const nonce = toBuffer(chunkNonce(noncePrefix, aad.chunkIndex));
    const additionalData = toBuffer(buildChunkAad(aad));
    const cryptoKey = await importKey(key, 'decrypt');

    try {
        return new Uint8Array(
            await subtle().decrypt(
                { name: 'AES-GCM', iv: nonce, additionalData, tagLength: GCM_TAG_LENGTH * 8 },
                cryptoKey,
                toBuffer(chunk.subarray(HEADER_LENGTH)),
            ),
        );
    } catch {
        /*
         | WebCrypto reports every decryption failure as an OperationError with
         | no detail, which is correct of it — distinguishing "wrong key" from
         | "bad tag" would be an oracle. It is reported here the same way a
         | failed payload is, naming the file and the chunk.
         */
        throw new IntegrityError(`${aad.context}[${aad.chunkIndex}]`, aad.subject);
    }
}
