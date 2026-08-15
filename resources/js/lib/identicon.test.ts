import { describe, expect, it } from 'vitest';

import { computeFingerprint, generateIdentity } from '@/crypto/identity';

import { IDENTICON_SIZE, identicon } from './identicon';

const fingerprintOf = () => generateIdentity().fingerprint;

describe('identicon', () => {
    it('is deterministic, so the same identity always draws the same picture', () => {
        const fingerprint = fingerprintOf();

        expect(identicon(fingerprint)).toEqual(identicon(fingerprint));
    });

    /** The property the whole thing exists for: a substituted key looks different. */
    it('changes when the fingerprint changes', () => {
        const a = generateIdentity();
        const b = generateIdentity();

        expect(identicon(a.fingerprint)).not.toEqual(identicon(b.fingerprint));
    });

    it('changes when a single bit of the fingerprint changes', () => {
        const fingerprint = fingerprintOf();
        const flipped = Uint8Array.from(fingerprint);
        // Non-null: a fingerprint is 32 bytes.
        flipped.set([flipped[0]! ^ 0x01], 0);

        expect(identicon(flipped)).not.toEqual(identicon(fingerprint));
    });

    /**
     * Every bit of the input has to reach the picture. Deriving from a slice
     * would leave two identities differing only in later bytes drawing the same
     * shape — the exact failure the identicon is meant to catch.
     */
    it('responds to a change in the last byte as readily as the first', () => {
        const fingerprint = fingerprintOf();
        const tail = Uint8Array.from(fingerprint);
        tail.set([tail[31]! ^ 0x80], 31);

        expect(identicon(tail)).not.toEqual(identicon(fingerprint));
    });

    it('is mirrored about the centre column', () => {
        const cells = identicon(fingerprintOf());

        for (const cell of cells) {
            const mirrored = IDENTICON_SIZE - 1 - cell.x;

            expect(cells).toContainEqual({ x: mirrored, y: cell.y, accent: cell.accent });
        }
    });

    it('stays inside the grid', () => {
        for (const { x, y } of identicon(fingerprintOf())) {
            expect(x).toBeGreaterThanOrEqual(0);
            expect(x).toBeLessThan(IDENTICON_SIZE);
            expect(y).toBeGreaterThanOrEqual(0);
            expect(y).toBeLessThan(IDENTICON_SIZE);
        }
    });

    it('never emits the same cell twice', () => {
        const cells = identicon(fingerprintOf());
        const keys = cells.map(({ x, y }) => `${x},${y}`);

        expect(new Set(keys).size).toBe(keys.length);
    });

    /**
     * A grid that came out all-on or all-off for a plausible input would be
     * useless, so a spread of identities is checked to produce a spread of
     * densities rather than trusting the hash to behave.
     */
    it('produces varied densities across many identities', () => {
        const densities = new Set(Array.from({ length: 50 }, () => identicon(fingerprintOf()).length));

        expect(densities.size).toBeGreaterThan(5);
    });

    it('draws distinct pictures for a hundred distinct identities', () => {
        const pictures = Array.from({ length: 100 }, () => JSON.stringify(identicon(fingerprintOf())));

        expect(new Set(pictures).size).toBe(100);
    });

    it('accepts a fingerprint computed from real keys', () => {
        const { ed25519, x25519 } = generateIdentity();

        expect(() => identicon(computeFingerprint(ed25519.publicKey, x25519.publicKey))).not.toThrow();
    });
});
