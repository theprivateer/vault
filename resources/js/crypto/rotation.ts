/**
 * Rotation certificates: the statement "the key you verified says this one
 * replaces it".
 *
 * When somebody replaces their identity keys, every peer who pinned the old
 * fingerprint sees a change — and a changed pin is, by design, indistinguishable
 * from a server substituting its own key. That hard stop is correct and it stays.
 * What it lacks is information: "they rotated" and "you are being attacked" both
 * arrive as the same red screen, and a person shown the same screen for both
 * learns to click through it.
 *
 * A certificate separates them. The **old** Ed25519 key signs a statement naming
 * its successor, so a peer holding the old fingerprint can check whether the new
 * keys were introduced by the keys they already verified.
 *
 * **It is not an accept.** Three limits, all of them stated in the interface
 * rather than only here:
 *
 * 1. A compromised old key signs a perfect certificate. That is the case
 *    rotation most often exists for, so a valid certificate is evidence about
 *    continuity of *key*, never about continuity of *person*.
 * 2. It is served by the server, which is the adversary this layer detects. The
 *    old public keys arrive alongside it, so the peer recomputes their
 *    fingerprint and compares it against their own pin before believing any of
 *    it — a certificate verified against a key the server supplied would be the
 *    forger checking the forgery.
 * 3. Exactly one link is followed. A peer whose pin is two rotations stale has
 *    not spoken to this person across two key changes, and re-verifying out of
 *    band is the honest answer rather than a longer chain of the server's own
 *    assertions.
 *
 * Spec: docs/03-cryptographic-design.md#identity-key-rotation
 */
import { ed25519 } from '@noble/curves/ed25519.js';

import { InvalidParameterError } from './errors';
import { concat, utf8ToBytes } from './primitives';

/**
 * Domain separator. Without one, this statement and a grant and an audit entry
 * are all Ed25519 signatures by the same key over some JSON, and a signature
 * made for one could be presented as another.
 */
export const ROTATION_SIGNATURE_CONTEXT = 'vault:rotation:v1';

export const ROTATION_VERSION = 1;

const SIGNATURE_LENGTH = 64;

const PUBLIC_KEY_LENGTH = 32;

export interface RotationStatement {
    /** Whose identity this is. */
    userUuid: string;
    /** The fingerprint being retired, lowercase hex. */
    previousFingerprint: string;
    /** The fingerprint taking over, lowercase hex. */
    fingerprint: string;
    /** ISO 8601, UTC, second precision. */
    rotatedAt: string;
}

/**
 * Field order for the canonical form.
 *
 * Fixed explicitly for the same reason a grant's is: these bytes are what the
 * signature commits to, and two clients disagreeing about the order would
 * produce signatures neither could verify.
 */
const CANONICAL_FIELDS = ['v', 'userUuid', 'previousFingerprint', 'fingerprint', 'rotatedAt'] as const;

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

const FINGERPRINT_PATTERN = /^[0-9a-f]{64}$/;

const TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

/**
 * Serialises to the exact bytes that get signed and stored.
 *
 * Throws on invalid input: a certificate being written is our own data. The
 * asymmetry with `verifyRotation`, which never throws, is the same one running
 * through `grant.ts` and `identity.ts` — strict about what we produce, forgiving
 * about how we report what we receive.
 */
export function canonicaliseRotation(statement: RotationStatement): string {
    if (!UUID_PATTERN.test(statement.userUuid)) {
        throw new InvalidParameterError(
            `Rotation userUuid must be a lowercase UUID, received: ${statement.userUuid}`,
        );
    }

    for (const field of ['previousFingerprint', 'fingerprint'] as const) {
        if (!FINGERPRINT_PATTERN.test(statement[field])) {
            throw new InvalidParameterError(
                `Rotation ${field} must be 64 lowercase hex characters, received: ${statement[field]}`,
            );
        }
    }

    /*
     | A statement that retires a fingerprint in favour of itself says nothing
     | and would verify perfectly, which makes it the ideal shape for a replay:
     | present an old certificate as evidence that nothing changed. Refused at
     | the point it would be created.
     */
    if (statement.previousFingerprint === statement.fingerprint) {
        throw new InvalidParameterError('A rotation must name a different fingerprint than it replaces.');
    }

    if (!TIMESTAMP_PATTERN.test(statement.rotatedAt)) {
        throw new InvalidParameterError(
            `Rotation rotatedAt must be ISO 8601 UTC to the second, received: ${statement.rotatedAt}`,
        );
    }

    return JSON.stringify({ v: ROTATION_VERSION, ...statement }, [...CANONICAL_FIELDS]);
}

/** The current time in the format a certificate records. */
export function rotationTimestamp(at: Date = new Date()): string {
    return `${at.toISOString().slice(0, 19)}Z`;
}

export interface SignedRotation {
    /** The canonical JSON, stored verbatim so signatures outlive format changes. */
    payload: string;
    signature: Uint8Array;
}

/**
 * Signs with the key being retired.
 *
 * The *outgoing* Ed25519 key, which is the entire point — a certificate signed
 * by the new key would attest only that the new key exists, which anybody
 * holding it could say about any key at all.
 */
export function signRotation(
    previousEd25519SecretKey: Uint8Array,
    statement: RotationStatement,
): SignedRotation {
    const payload = canonicaliseRotation(statement);

    return { payload, signature: ed25519.sign(signaturePayload(payload), previousEd25519SecretKey) };
}

export type RotationVerdict =
    | { certified: true; statement: RotationStatement }
    | { certified: false; reason: 'malformed' | 'signature' | 'mismatch'; detail: string };

/**
 * Whether the retired key really did introduce the new one.
 *
 * `expected` is what the peer independently knows: the fingerprint they pinned,
 * and the fingerprint they just recomputed from the keys they were served.
 * Passing both is what turns "a valid signature over some statement" into
 * evidence about *this* change — without the comparison, any genuine certificate
 * this person ever issued would certify any substitution.
 *
 * **Never throws.** Every argument came from the server.
 */
export function verifyRotation(
    signature: Uint8Array,
    payload: string,
    previousEd25519PublicKey: Uint8Array,
    expected: { userUuid: string; previousFingerprint: string; fingerprint: string },
): RotationVerdict {
    const statement = parseRotation(payload);

    if (!statement) {
        return { certified: false, reason: 'malformed', detail: 'The rotation notice could not be read.' };
    }

    if (signature.length !== SIGNATURE_LENGTH || previousEd25519PublicKey.length !== PUBLIC_KEY_LENGTH) {
        return {
            certified: false,
            reason: 'signature',
            detail: 'The rotation notice or the retired key is the wrong length.',
        };
    }

    if (!verifySignature(signature, payload, previousEd25519PublicKey)) {
        return {
            certified: false,
            reason: 'signature',
            detail: 'The rotation notice is not signed by the keys you verified.',
        };
    }

    const differences: ReadonlyArray<readonly [string, string, string]> = [
        ['a different account', statement.userUuid, expected.userUuid],
        ['a different retired key', statement.previousFingerprint, expected.previousFingerprint],
        ['a different replacement key', statement.fingerprint, expected.fingerprint],
    ];

    for (const [description, actual, wanted] of differences) {
        if (actual !== wanted) {
            return {
                certified: false,
                reason: 'mismatch',
                detail: `The rotation notice describes ${description}, not this change.`,
            };
        }
    }

    return { certified: true, statement };
}

/**
 * Parses without re-canonicalising, exactly as a grant is parsed.
 *
 * Comparing a re-serialisation would invalidate every certificate the day the
 * format changes, which is the one thing storing the exact signed bytes exists
 * to prevent.
 */
export function parseRotation(payload: string): RotationStatement | null {
    let parsed: unknown;

    try {
        parsed = JSON.parse(payload);
    } catch {
        return null;
    }

    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
        return null;
    }

    const fields = parsed as Record<string, unknown>;

    if (fields.v !== ROTATION_VERSION) {
        return null;
    }

    const { userUuid, previousFingerprint, fingerprint, rotatedAt } = fields;

    const wellFormed =
        typeof userUuid === 'string' &&
        UUID_PATTERN.test(userUuid) &&
        typeof previousFingerprint === 'string' &&
        FINGERPRINT_PATTERN.test(previousFingerprint) &&
        typeof fingerprint === 'string' &&
        FINGERPRINT_PATTERN.test(fingerprint) &&
        previousFingerprint !== fingerprint &&
        typeof rotatedAt === 'string' &&
        TIMESTAMP_PATTERN.test(rotatedAt);

    if (!wellFormed) {
        return null;
    }

    return { userUuid, previousFingerprint, fingerprint, rotatedAt };
}

function verifySignature(signature: Uint8Array, payload: string, publicKey: Uint8Array): boolean {
    try {
        return ed25519.verify(signature, signaturePayload(payload), publicKey);
    } catch {
        return false;
    }
}

function signaturePayload(payload: string): Uint8Array {
    return concat(utf8ToBytes(ROTATION_SIGNATURE_CONTEXT), utf8ToBytes('\0'), utf8ToBytes(payload));
}
