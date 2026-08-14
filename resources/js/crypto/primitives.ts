/**
 * Thin, typed wrappers over the audited primitives.
 *
 * The whole crypto dependency surface is three `@noble` packages: audited, pure
 * TypeScript, no transitive dependencies, no post-install scripts and no WASM.
 * The absence of WASM is load-bearing — it is what lets the CSP stay strict with
 * no 'wasm-unsafe-eval'. See docs/adr/0003-argon2id-implementation.md.
 *
 * This module exists so that swapping an implementation is a change in one file,
 * and so that call sites read as intent rather than configuration.
 */
import { argon2id } from '@noble/hashes/argon2.js';
import { blake2b } from '@noble/hashes/blake2.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { utf8ToBytes as nobleUtf8ToBytes } from '@noble/hashes/utils.js';

import { InvalidParameterError } from './errors';

export { nobleUtf8ToBytes as utf8ToBytes };

/** Symmetric keys, KEKs, item keys and vault keys are all 32 bytes. */
export const KEY_LENGTH = 32;

/** XChaCha20-Poly1305. A 192-bit nonce is safe to generate randomly. */
export const NONCE_LENGTH = 24;

/** Poly1305 authentication tag. */
export const TAG_LENGTH = 16;

/**
 * Argon2id parameters. Stored per-user in the database rather than hardcoded, so
 * they can be raised later without a flag day — see "Parameter upgrades" in
 * docs/03-cryptographic-design.md.
 */
export interface KdfParams {
    /** Memory cost in KiB. */
    m: number;
    /** Time cost (passes). */
    t: number;
    /** Parallelism. */
    p: number;
}

/**
 * Current defaults. Measured at 731 ms on an Apple M1 (ADR-0003).
 */
export const DEFAULT_KDF_PARAMS: KdfParams = { m: 64 * 1024, t: 3, p: 1 };

/** Length of the combined KEK + auth key output of the password KDF. */
export const STRETCHED_LENGTH = 64;

export function randomBytes(length: number): Uint8Array {
    if (!Number.isSafeInteger(length) || length < 1) {
        throw new InvalidParameterError(`Cannot generate ${length} random bytes.`);
    }

    return crypto.getRandomValues(new Uint8Array(length));
}

/**
 * Stretches a low-entropy password into 64 bytes of key material.
 *
 * Slow by design: this is the only thing standing between a stolen database and
 * an offline dictionary attack (adversary A1).
 */
export function stretchPassword(
    password: string,
    salt: Uint8Array,
    params: KdfParams = DEFAULT_KDF_PARAMS,
): Uint8Array {
    if (password.length === 0) {
        throw new InvalidParameterError('Refusing to derive a key from an empty password.');
    }

    if (salt.length < 16) {
        throw new InvalidParameterError(`KDF salt must be at least 16 bytes, received ${salt.length}.`);
    }

    return argon2id(password, salt, {
        m: params.m,
        t: params.t,
        p: params.p,
        dkLen: STRETCHED_LENGTH,
    });
}

/**
 * Derives key material from an input that is *already* high entropy — a recovery
 * code, or an ECDH shared secret.
 *
 * Using HKDF here rather than Argon2id is a deliberate distinction, not an
 * inconsistency: a slow KDF buys nothing against 128+ bits of uniform
 * randomness, and would only cost the user time.
 */
export function deriveKey(
    input: Uint8Array,
    salt: Uint8Array | undefined,
    info: string,
    length: number = KEY_LENGTH,
): Uint8Array {
    return hkdf(sha256, input, salt, nobleUtf8ToBytes(info), length);
}

/** BLAKE2b-256, used for fingerprints and the audit hash chain. */
export function hash256(data: Uint8Array): Uint8Array {
    return blake2b(data, { dkLen: 32 });
}

/**
 * Compares two byte arrays without leaking their contents through timing.
 *
 * Length is compared first and non-constant-time, which is fine: the lengths
 * involved are public.
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) {
        return false;
    }

    let difference = 0;
    // The lengths are equal, so every index is in range for both arrays. The
    // assertion states that rather than adding an unreachable fallback branch.
    a.forEach((byte, index) => {
        difference |= byte ^ b[index]!;
    });

    return difference === 0;
}

/**
 * Overwrites key material with zeros.
 *
 * Best-effort hygiene, not a guarantee. A garbage-collected runtime may have
 * copied these bytes during compaction, and structuredClone across a Worker
 * boundary copies them by definition. Terminating the Worker on lock is the
 * reliable erasure; this reduces the window for everything else.
 */
export function zeroise(...arrays: Uint8Array[]): void {
    for (const array of arrays) {
        array.fill(0);
    }
}

export function concat(...arrays: Uint8Array[]): Uint8Array {
    const result = new Uint8Array(arrays.reduce((sum, array) => sum + array.length, 0));

    let offset = 0;
    for (const array of arrays) {
        result.set(array, offset);
        offset += array.length;
    }

    return result;
}
