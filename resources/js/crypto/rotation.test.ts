/**
 * Rotation certificates, and the four ways one must fail.
 *
 * The certificate exists to separate "they rotated their keys" from "the server
 * substituted its own", which arrive at a peer as the same changed fingerprint.
 * So the tests worth having are the ones that check it cannot be made to say the
 * second while meaning the first: signed by the wrong key, describing a
 * different change, replayed from another account, or naming itself.
 *
 * It is never an accept, and one test says so directly rather than leaving that
 * to prose: a compromised old key signs a perfect certificate, which is the case
 * rotation most often exists for.
 */
import { ed25519 } from '@noble/curves/ed25519.js';
import { describe, expect, it } from 'vitest';

import { InvalidParameterError } from './errors';
import { fingerprintHex } from './grant';
import { computeFingerprint, generateIdentity } from './identity';
import {
    ROTATION_SIGNATURE_CONTEXT,
    canonicaliseRotation,
    parseRotation,
    rotationTimestamp,
    signRotation,
    verifyRotation,
    type RotationStatement,
} from './rotation';

const USER = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f6';

function fingerprintOf(identity: ReturnType<typeof generateIdentity>): string {
    return fingerprintHex(identity.fingerprint);
}

/** A retired identity, its replacement, and the certificate joining them. */
function rotation() {
    const previous = generateIdentity();
    const next = generateIdentity();

    const statement: RotationStatement = {
        userUuid: USER,
        previousFingerprint: fingerprintOf(previous),
        fingerprint: fingerprintOf(next),
        rotatedAt: '2026-08-16T09:00:00Z',
    };

    return {
        previous,
        next,
        statement,
        signed: signRotation(previous.ed25519.secretKey, statement),
        expected: {
            userUuid: USER,
            previousFingerprint: statement.previousFingerprint,
            fingerprint: statement.fingerprint,
        },
    };
}

describe('signing and verifying', () => {
    it('certifies a rotation against the keys being retired', () => {
        const { previous, signed, expected, statement } = rotation();

        expect(
            verifyRotation(signed.signature, signed.payload, previous.ed25519.publicKey, expected),
        ).toEqual({ certified: true, statement });
    });

    /*
     | The whole point. A certificate signed by the *new* key attests only that
     | the new key exists, which anybody holding any key could say about it — so
     | verifying against the incoming key rather than the retired one would
     | certify every substitution perfectly.
     */
    it('gives a peer nothing when the certificate is signed by the incoming key', () => {
        const { previous, next, statement, expected } = rotation();

        // Self-certified: the new key vouching for itself, which is what a
        // server substituting a key of its own would be able to produce.
        const signed = signRotation(next.ed25519.secretKey, statement);

        // The peer always checks against the key *they pinned*, which is the
        // retired one — so a self-certified rotation fails for them.
        expect(
            verifyRotation(signed.signature, signed.payload, previous.ed25519.publicKey, expected),
        ).toMatchObject({ certified: false, reason: 'signature' });
    });

    it('refuses a signature from an unrelated key', () => {
        const { signed, expected } = rotation();
        const stranger = generateIdentity();

        expect(
            verifyRotation(signed.signature, signed.payload, stranger.ed25519.publicKey, expected),
        ).toMatchObject({ certified: false, reason: 'signature' });
    });

    it('refuses a tampered signature or a wrong-length key', () => {
        const { previous, signed, expected } = rotation();

        expect(
            verifyRotation(
                signed.signature.slice(0, 63),
                signed.payload,
                previous.ed25519.publicKey,
                expected,
            ),
        ).toMatchObject({ certified: false, reason: 'signature' });

        expect(
            verifyRotation(
                signed.signature,
                signed.payload,
                previous.ed25519.publicKey.slice(0, 31),
                expected,
            ),
        ).toMatchObject({ certified: false, reason: 'signature' });
    });

    /*
     | A valid signature over *some* statement is not evidence about *this*
     | change. Without comparing against what the peer independently knows — the
     | fingerprint they pinned, and the one they just recomputed — any genuine
     | certificate this person ever issued would certify any substitution.
     */
    it('refuses a genuine certificate describing a different change', () => {
        const { previous, signed, expected } = rotation();
        const somebodyElse = generateIdentity();

        expect(
            verifyRotation(signed.signature, signed.payload, previous.ed25519.publicKey, {
                ...expected,
                fingerprint: fingerprintOf(somebodyElse),
            }),
        ).toMatchObject({ certified: false, reason: 'mismatch' });

        expect(
            verifyRotation(signed.signature, signed.payload, previous.ed25519.publicKey, {
                ...expected,
                previousFingerprint: fingerprintOf(somebodyElse),
            }),
        ).toMatchObject({ certified: false, reason: 'mismatch' });

        expect(
            verifyRotation(signed.signature, signed.payload, previous.ed25519.publicKey, {
                ...expected,
                userUuid: '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f7',
            }),
        ).toMatchObject({ certified: false, reason: 'mismatch' });
    });

    /*
     | Stated as a test rather than left to the prose, because it is the limit
     | people most want to forget: the key that signs a rotation is the key you
     | are worried about. Continuity of key is not continuity of person, which is
     | why the interface still refuses to accept without an out-of-band check.
     */
    it('certifies a rotation performed by whoever holds the old key, attacker included', () => {
        const stolen = generateIdentity();
        const attacker = generateIdentity();

        const statement: RotationStatement = {
            userUuid: USER,
            previousFingerprint: fingerprintOf(stolen),
            fingerprint: fingerprintOf(attacker),
            rotatedAt: rotationTimestamp(new Date('2026-08-16T09:00:00Z')),
        };

        const signed = signRotation(stolen.ed25519.secretKey, statement);

        expect(
            verifyRotation(signed.signature, signed.payload, stolen.ed25519.publicKey, {
                userUuid: USER,
                previousFingerprint: statement.previousFingerprint,
                fingerprint: statement.fingerprint,
            }).certified,
        ).toBe(true);
    });
});

describe('the signed bytes', () => {
    it('carries a domain separator, so it cannot be replayed as a grant', () => {
        const { previous, signed } = rotation();

        // Verified without the separator: a signature over the bare payload
        // would mean any Ed25519 statement by this key could be presented here.
        expect(
            ed25519.verify(
                signed.signature,
                new TextEncoder().encode(signed.payload),
                previous.ed25519.publicKey,
            ),
        ).toBe(false);

        expect(ROTATION_SIGNATURE_CONTEXT).toBe('vault:rotation:v1');
    });

    it('serialises in a fixed field order', () => {
        const { statement } = rotation();

        expect(canonicaliseRotation(statement)).toBe(
            JSON.stringify({
                v: 1,
                userUuid: statement.userUuid,
                previousFingerprint: statement.previousFingerprint,
                fingerprint: statement.fingerprint,
                rotatedAt: statement.rotatedAt,
            }),
        );
    });

    it('formats a timestamp to the second, in UTC', () => {
        expect(rotationTimestamp(new Date('2026-08-16T09:00:00.123Z'))).toBe('2026-08-16T09:00:00Z');
    });

    /*
     | A statement retiring a fingerprint in favour of itself would verify
     | perfectly while saying nothing — the ideal shape for presenting an old
     | certificate as evidence that nothing changed. Refused where it would be
     | created and where it would be read.
     */
    it('refuses to certify a key as its own replacement', () => {
        const { statement } = rotation();

        expect(() =>
            canonicaliseRotation({ ...statement, fingerprint: statement.previousFingerprint }),
        ).toThrow(InvalidParameterError);

        expect(
            parseRotation(
                JSON.stringify({
                    v: 1,
                    userUuid: USER,
                    previousFingerprint: statement.previousFingerprint,
                    fingerprint: statement.previousFingerprint,
                    rotatedAt: statement.rotatedAt,
                }),
            ),
        ).toBeNull();
    });

    it.each([
        ['not-a-uuid', 'userUuid'],
        [USER, 'previousFingerprint'],
        [USER, 'fingerprint'],
        [USER, 'rotatedAt'],
    ])('refuses malformed input when writing (%s / %s)', (userUuid, field) => {
        const { statement } = rotation();

        expect(() => canonicaliseRotation({ ...statement, userUuid, [field]: 'nonsense' })).toThrow(
            InvalidParameterError,
        );
    });

    it('computes the retired fingerprint from the keys, not from a label', () => {
        const { previous, statement } = rotation();

        expect(statement.previousFingerprint).toBe(
            fingerprintHex(computeFingerprint(previous.ed25519.publicKey, previous.x25519.publicKey)),
        );
    });
});

describe('reading a statement back', () => {
    it('rejects anything that is not a rotation this client understands', () => {
        const { statement } = rotation();
        const valid = canonicaliseRotation(statement);

        expect(parseRotation(valid)).toEqual(statement);

        expect(parseRotation('not json')).toBeNull();
        expect(parseRotation('null')).toBeNull();
        expect(parseRotation('[]')).toBeNull();
        expect(parseRotation('"a string"')).toBeNull();
        expect(parseRotation(JSON.stringify({ ...JSON.parse(valid), v: 2 }))).toBeNull();
        expect(parseRotation(JSON.stringify({ ...JSON.parse(valid), userUuid: 'nope' }))).toBeNull();
        expect(parseRotation(JSON.stringify({ ...JSON.parse(valid), fingerprint: 'nope' }))).toBeNull();
        expect(
            parseRotation(JSON.stringify({ ...JSON.parse(valid), previousFingerprint: 'nope' })),
        ).toBeNull();
        expect(parseRotation(JSON.stringify({ ...JSON.parse(valid), rotatedAt: 'yesterday' }))).toBeNull();
    });

    it('reports an unreadable payload rather than throwing', () => {
        const { previous, expected } = rotation();

        expect(
            verifyRotation(new Uint8Array(64), 'not json', previous.ed25519.publicKey, expected),
        ).toMatchObject({ certified: false, reason: 'malformed' });
    });
});
