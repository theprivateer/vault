/**
 * A user's cryptographic identity: an X25519 pair for receiving sealed vault
 * keys, and an Ed25519 pair for signing grants and audit entries.
 *
 * The server serves these public keys, which means the server can lie about
 * them. The self-signature proves the two keys were published together by
 * whoever holds the Ed25519 private key; the fingerprint is what a human
 * compares out of band. Neither makes the database a root of trust — the user's
 * out-of-band comparison is. See docs/03-cryptographic-design.md#sharing-a-vault-d8
 */
import { ED25519_TORSION_SUBGROUP, ed25519 } from '@noble/curves/ed25519.js';
import { bytesToHex } from '@noble/hashes/utils.js';

import { encodeBase32, group } from './encoding';
import { InvalidParameterError } from './errors';
import type { KeyPair } from './keys';
import { generateX25519KeyPair } from './keys';
import { concat, hash256, utf8ToBytes } from './primitives';

const PUBLIC_KEY_LENGTH = 32;

const SIGNATURE_LENGTH = 64;

/** Domain separator, so a self-signature can never be replayed as a grant signature. */
const SELF_SIGNATURE_CONTEXT = 'vault:identity:v1';

/** 15 bytes of the fingerprint render as exactly 24 base32 characters. */
const FINGERPRINT_DISPLAY_BYTES = 15;

/**
 * The eight points of the Ed25519 torsion subgroup, including the all-zero
 * encoding.
 *
 * These must be rejected as public keys. Ed25519 verification accepts an
 * all-zero signature against an all-zero public key for any message, so without
 * this check a malicious server could publish a degenerate identity whose
 * self-signature "verifies" — exactly the substitution the self-signature exists
 * to detect. See docs/03-cryptographic-design.md#sharing-a-vault-d8.
 */
const SMALL_ORDER_POINTS: ReadonlySet<string> = new Set(ED25519_TORSION_SUBGROUP);

function isSmallOrder(publicKey: Uint8Array): boolean {
    return SMALL_ORDER_POINTS.has(bytesToHex(publicKey));
}

export interface Identity {
    x25519: KeyPair;
    ed25519: KeyPair;
    /** BLAKE2b-256 over both public keys. */
    fingerprint: Uint8Array;
    /** Ed25519 over both public keys, proving they were published together. */
    selfSignature: Uint8Array;
}

export function generateIdentity(): Identity {
    const x = generateX25519KeyPair();

    const edSecret = ed25519.utils.randomSecretKey();
    const ed: KeyPair = { secretKey: edSecret, publicKey: ed25519.getPublicKey(edSecret) };

    return {
        x25519: x,
        ed25519: ed,
        fingerprint: computeFingerprint(ed.publicKey, x.publicKey),
        selfSignature: signPublicKeys(ed.secretKey, ed.publicKey, x.publicKey),
    };
}

export function computeFingerprint(ed25519PublicKey: Uint8Array, x25519PublicKey: Uint8Array): Uint8Array {
    assertPublicKey(ed25519PublicKey, 'Ed25519');
    assertPublicKey(x25519PublicKey, 'X25519');

    return hash256(concat(ed25519PublicKey, x25519PublicKey));
}

/**
 * Renders a fingerprint as six four-character groups for out-of-band comparison.
 *
 * Truncated to 120 bits, which is far beyond what a second-preimage attack
 * could reach and is short enough that a person will actually read it out. The
 * full 256-bit value is what gets pinned and compared programmatically.
 */
export function formatFingerprint(fingerprint: Uint8Array): string {
    if (fingerprint.length < FINGERPRINT_DISPLAY_BYTES) {
        throw new InvalidParameterError(
            `Fingerprint must be at least ${FINGERPRINT_DISPLAY_BYTES} bytes, received ${fingerprint.length}.`,
        );
    }

    return group(encodeBase32(fingerprint.subarray(0, FINGERPRINT_DISPLAY_BYTES)));
}

export function signPublicKeys(
    ed25519SecretKey: Uint8Array,
    ed25519PublicKey: Uint8Array,
    x25519PublicKey: Uint8Array,
): Uint8Array {
    return ed25519.sign(selfSignaturePayload(ed25519PublicKey, x25519PublicKey), ed25519SecretKey);
}

/**
 * Verifies that both public keys were published together by the holder of the
 * Ed25519 private key.
 *
 * **Never throws.** Everything passed in here comes from the server and is
 * therefore untrusted, so malformed, degenerate and simply-wrong input are all
 * expected conditions that render as a warning. Signing throws on bad input
 * because that would be our own data; verifying does not.
 */
export function verifyPublicKeys(
    signature: Uint8Array,
    ed25519PublicKey: Uint8Array,
    x25519PublicKey: Uint8Array,
): boolean {
    const wellFormed =
        signature.length === SIGNATURE_LENGTH &&
        ed25519PublicKey.length === PUBLIC_KEY_LENGTH &&
        x25519PublicKey.length === PUBLIC_KEY_LENGTH;

    if (!wellFormed || isSmallOrder(ed25519PublicKey) || isAllZero(x25519PublicKey)) {
        return false;
    }

    try {
        return ed25519.verify(
            signature,
            selfSignaturePayload(ed25519PublicKey, x25519PublicKey),
            ed25519PublicKey,
        );
    } catch {
        return false;
    }
}

function selfSignaturePayload(ed25519PublicKey: Uint8Array, x25519PublicKey: Uint8Array): Uint8Array {
    assertPublicKey(ed25519PublicKey, 'Ed25519');
    assertPublicKey(x25519PublicKey, 'X25519');

    return concat(utf8ToBytes(SELF_SIGNATURE_CONTEXT), ed25519PublicKey, x25519PublicKey);
}

/**
 * X25519's small-order points are refused by `getSharedSecret` at the moment
 * they would matter, so only the trivially degenerate all-zero key needs
 * rejecting here.
 */
function isAllZero(key: Uint8Array): boolean {
    return key.every((byte) => byte === 0);
}

function assertPublicKey(key: Uint8Array, label: string): void {
    if (key.length !== PUBLIC_KEY_LENGTH) {
        throw new InvalidParameterError(
            `${label} public key must be ${PUBLIC_KEY_LENGTH} bytes, received ${key.length}.`,
        );
    }
}
