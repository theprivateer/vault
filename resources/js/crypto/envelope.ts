/**
 * The envelope every ciphertext at rest is wrapped in.
 *
 *   ┌────────┬────────┬──────────┬────────────────┬──────────┐
 *   │ ver    │ alg    │ nonce    │ ciphertext     │ tag      │
 *   │ 1 byte │ 1 byte │ 24 bytes │ variable       │ 16 bytes │
 *   └────────┴────────┴──────────┴────────────────┴──────────┘
 *
 * `ver` allows the envelope structure to change; `alg` allows the primitive to
 * change. A decryptor rejects anything it does not recognise rather than
 * falling back, so an attempt to downgrade the algorithm fails loudly.
 *
 * Spec: docs/03-cryptographic-design.md#envelope-format
 */
import type { AadParams } from './aad';
import { buildAad } from './aad';
import {
    IntegrityError,
    InvalidParameterError,
    MalformedEnvelopeError,
    UnsupportedEnvelopeError,
} from './errors';
import { KEY_LENGTH, NONCE_LENGTH, TAG_LENGTH, randomBytes } from './primitives';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';

export const ENVELOPE_VERSION = 1;

export const ALG_XCHACHA20_POLY1305 = 1;

const HEADER_LENGTH = 2;

const NONCE_OFFSET = HEADER_LENGTH;

const BODY_OFFSET = HEADER_LENGTH + NONCE_LENGTH;

/** An empty plaintext still costs a header, a nonce and a tag. */
export const MIN_ENVELOPE_LENGTH = BODY_OFFSET + TAG_LENGTH;

function assertKey(key: Uint8Array): void {
    if (key.length !== KEY_LENGTH) {
        throw new InvalidParameterError(`Key must be ${KEY_LENGTH} bytes, received ${key.length}.`);
    }
}

/**
 * Encrypts under `key`, bound to the record described by `aad`.
 *
 * `aad` is a required positional parameter with no default. That is the point:
 * forgetting to bind a ciphertext to its record is a type error at the call
 * site rather than a silent security hole discovered later (SR4).
 */
export function seal(key: Uint8Array, plaintext: Uint8Array, aad: AadParams): Uint8Array {
    assertKey(key);

    const nonce = randomBytes(NONCE_LENGTH);
    const body = xchacha20poly1305(key, nonce, buildAad(aad)).encrypt(plaintext);

    const envelope = new Uint8Array(BODY_OFFSET + body.length);
    envelope[0] = ENVELOPE_VERSION;
    envelope[1] = ALG_XCHACHA20_POLY1305;
    envelope.set(nonce, NONCE_OFFSET);
    envelope.set(body, BODY_OFFSET);

    return envelope;
}

/**
 * Decrypts an envelope, verifying it was sealed under `key` and bound to the
 * record described by `aad`.
 *
 * Throws on every failure path. Never returns a null, an empty array, or a
 * partially-decrypted result.
 */
export function open(key: Uint8Array, envelope: Uint8Array, aad: AadParams): Uint8Array {
    assertKey(key);

    if (envelope.length < MIN_ENVELOPE_LENGTH) {
        throw new MalformedEnvelopeError(
            `Envelope is ${envelope.length} bytes, minimum is ${MIN_ENVELOPE_LENGTH}.`,
        );
    }

    // Both indices are in range: the length check above guarantees at least
    // MIN_ENVELOPE_LENGTH bytes.
    const version = envelope[0]!;
    const algorithm = envelope[1]!;

    if (version !== ENVELOPE_VERSION || algorithm !== ALG_XCHACHA20_POLY1305) {
        throw new UnsupportedEnvelopeError(version, algorithm);
    }

    const nonce = envelope.subarray(NONCE_OFFSET, BODY_OFFSET);
    const body = envelope.subarray(BODY_OFFSET);

    try {
        return xchacha20poly1305(key, nonce, buildAad(aad)).decrypt(body);
    } catch (cause) {
        // An InvalidParameterError from buildAad is a programming mistake, not a
        // tampered ciphertext, and must not be disguised as one.
        if (cause instanceof InvalidParameterError) {
            throw cause;
        }

        throw new IntegrityError(aad.context, aad.subject);
    }
}
