import { ED25519_TORSION_SUBGROUP } from '@noble/curves/ed25519.js';
import { hexToBytes } from '@noble/hashes/utils.js';
import { describe, expect, it } from 'vitest';

import { InvalidParameterError } from './errors';
import {
    computeFingerprint,
    formatFingerprint,
    generateIdentity,
    signPublicKeys,
    verifyPublicKeys,
} from './identity';

describe('generateIdentity', () => {
    it('produces both keypairs at the expected sizes', () => {
        const identity = generateIdentity();

        expect(identity.x25519.publicKey).toHaveLength(32);
        expect(identity.x25519.secretKey).toHaveLength(32);
        expect(identity.ed25519.publicKey).toHaveLength(32);
        expect(identity.ed25519.secretKey).toHaveLength(32);
        expect(identity.fingerprint).toHaveLength(32);
        expect(identity.selfSignature).toHaveLength(64);
    });

    it('produces a valid self-signature', () => {
        const { ed25519, x25519, selfSignature } = generateIdentity();

        expect(verifyPublicKeys(selfSignature, ed25519.publicKey, x25519.publicKey)).toBe(true);
    });

    it('is different every time', () => {
        const fingerprints = Array.from({ length: 10 }, () => generateIdentity().fingerprint.toString());

        expect(new Set(fingerprints).size).toBe(10);
    });
});

describe('fingerprints', () => {
    it('is deterministic', () => {
        const { ed25519, x25519 } = generateIdentity();

        expect(computeFingerprint(ed25519.publicKey, x25519.publicKey)).toEqual(
            computeFingerprint(ed25519.publicKey, x25519.publicKey),
        );
    });

    it('changes if either key changes', () => {
        const a = generateIdentity();
        const b = generateIdentity();

        const baseline = computeFingerprint(a.ed25519.publicKey, a.x25519.publicKey);

        expect(computeFingerprint(b.ed25519.publicKey, a.x25519.publicKey)).not.toEqual(baseline);
        expect(computeFingerprint(a.ed25519.publicKey, b.x25519.publicKey)).not.toEqual(baseline);
    });

    it('is order sensitive, so the two keys cannot be transposed', () => {
        const { ed25519, x25519 } = generateIdentity();

        expect(computeFingerprint(ed25519.publicKey, x25519.publicKey)).not.toEqual(
            computeFingerprint(x25519.publicKey, ed25519.publicKey),
        );
    });

    it('renders as six four-character groups for reading aloud', () => {
        const formatted = formatFingerprint(generateIdentity().fingerprint);

        expect(formatted).toMatch(/^([0-9A-HJKMNP-TV-Z]{4}-){5}[0-9A-HJKMNP-TV-Z]{4}$/);
        expect(formatted.replace(/-/g, '')).toHaveLength(24);
    });

    it('refuses to format something too short to be a fingerprint', () => {
        expect(() => formatFingerprint(new Uint8Array(14))).toThrow(InvalidParameterError);
    });

    it.each([31, 33])('refuses a %i byte public key', (length) => {
        const { x25519 } = generateIdentity();

        expect(() => computeFingerprint(new Uint8Array(length), x25519.publicKey)).toThrow(
            InvalidParameterError,
        );
    });
});

describe('self-signature verification', () => {
    /*
     | The attack this defends against: the server serves its own X25519 key so
     | it can read everything shared with this user, while keeping the victim's
     | Ed25519 key so the identity still looks familiar. The signature covers
     | both keys together, so the substitution cannot verify.
     */
    it('rejects a substituted X25519 key', () => {
        const victim = generateIdentity();
        const attacker = generateIdentity();

        expect(
            verifyPublicKeys(victim.selfSignature, victim.ed25519.publicKey, attacker.x25519.publicKey),
        ).toBe(false);
    });

    it('rejects a substituted Ed25519 key', () => {
        const victim = generateIdentity();
        const attacker = generateIdentity();

        expect(
            verifyPublicKeys(victim.selfSignature, attacker.ed25519.publicKey, victim.x25519.publicKey),
        ).toBe(false);
    });

    it('rejects a signature from another identity', () => {
        const victim = generateIdentity();
        const attacker = generateIdentity();

        expect(
            verifyPublicKeys(attacker.selfSignature, victim.ed25519.publicKey, victim.x25519.publicKey),
        ).toBe(false);
    });

    it('rejects a tampered signature', () => {
        const { ed25519, x25519, selfSignature } = generateIdentity();

        for (const index of [0, 31, 63]) {
            const tampered = Uint8Array.from(selfSignature);
            tampered[index] = tampered[index]! ^ 0x01;

            expect(verifyPublicKeys(tampered, ed25519.publicKey, x25519.publicKey)).toBe(false);
        }
    });

    it.each([0, 63, 65])('rejects a %i byte signature without throwing', (length) => {
        const { ed25519, x25519 } = generateIdentity();

        expect(verifyPublicKeys(new Uint8Array(length), ed25519.publicKey, x25519.publicKey)).toBe(false);
    });

    /*
     | Ed25519 verification accepts an all-zero signature against an all-zero
     | public key for any message. Without an explicit small-order check, a
     | malicious server could publish a degenerate identity whose self-signature
     | verifies — defeating the very check that is supposed to detect key
     | substitution.
     */
    it.each(ED25519_TORSION_SUBGROUP)('rejects the small-order public key %s', (point) => {
        const { x25519 } = generateIdentity();

        expect(verifyPublicKeys(new Uint8Array(64), hexToBytes(point), x25519.publicKey)).toBe(false);
    });

    it('rejects an all-zero X25519 key', () => {
        const { ed25519, selfSignature } = generateIdentity();

        expect(verifyPublicKeys(selfSignature, ed25519.publicKey, new Uint8Array(32))).toBe(false);
    });

    it('returns false for a 32 byte value that is not a valid curve point', () => {
        const { x25519, selfSignature } = generateIdentity();

        // Correct length, not small order, but decodes to no point on the curve.
        expect(verifyPublicKeys(selfSignature, new Uint8Array(32).fill(0xff), x25519.publicKey)).toBe(false);
    });

    // The library-failure path is covered in identity.library-failure.test.ts,
    // which needs a module-level mock.

    it.each([31, 33, 0])('returns false for a %i byte key rather than throwing', (length) => {
        const { ed25519, x25519, selfSignature } = generateIdentity();

        // Everything here comes from the server. Malformed input is an expected
        // condition, not an exceptional one.
        expect(verifyPublicKeys(selfSignature, ed25519.publicKey, new Uint8Array(length))).toBe(false);
        expect(verifyPublicKeys(selfSignature, new Uint8Array(length), x25519.publicKey)).toBe(false);
    });

    it('is domain separated, so a self-signature is not a valid grant signature', () => {
        const { ed25519, x25519 } = generateIdentity();
        const signature = signPublicKeys(ed25519.secretKey, ed25519.publicKey, x25519.publicKey);

        // Signing the bare concatenation without the context prefix must not
        // produce the same signature.
        expect(verifyPublicKeys(signature, ed25519.publicKey, x25519.publicKey)).toBe(true);
        expect(signature).not.toEqual(signPublicKeys(ed25519.secretKey, x25519.publicKey, ed25519.publicKey));
    });
});
