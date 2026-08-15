import { ed25519 } from '@noble/curves/ed25519.js';
import { describe, expect, it } from 'vitest';

import { InvalidParameterError } from './errors';
import type { Grant } from './grant';
import {
    GRANT_SIGNATURE_CONTEXT,
    canonicaliseGrant,
    fingerprintHex,
    grantTimestamp,
    parseGrant,
    signGrant,
    verifyGrant,
} from './grant';
import { generateIdentity } from './identity';
import { concat, utf8ToBytes } from './primitives';

const granter = generateIdentity();

const grant: Grant = {
    vaultUuid: '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f6',
    recipientUuid: '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f7',
    recipientFingerprint: 'a'.repeat(64),
    role: 'editor',
    keyEpoch: 1,
    grantedAt: '2026-08-15T09:00:00Z',
};

const signed = signGrant(granter.ed25519.secretKey, grant);

const verify = (overrides: Partial<Grant> = {}) =>
    verifyGrant(signed.signature, signed.payload, granter.ed25519.publicKey, { ...grant, ...overrides });

describe('canonicaliseGrant', () => {
    it('is deterministic', () => {
        expect(canonicaliseGrant(grant)).toBe(canonicaliseGrant({ ...grant }));
    });

    /**
     * The bytes are what a signature commits to. Two clients that disagreed
     * about field order would produce signatures neither could verify, so the
     * order is asserted rather than left to whatever the object literal happened
     * to be built with.
     */
    it('emits fields in a fixed order regardless of how the object was built', () => {
        const reordered: Grant = {
            grantedAt: grant.grantedAt,
            role: grant.role,
            keyEpoch: grant.keyEpoch,
            recipientFingerprint: grant.recipientFingerprint,
            recipientUuid: grant.recipientUuid,
            vaultUuid: grant.vaultUuid,
        };

        expect(canonicaliseGrant(reordered)).toBe(canonicaliseGrant(grant));
        expect(canonicaliseGrant(grant)).toMatch(
            /^\{"v":1,"vaultUuid":".+","recipientUuid":".+","recipientFingerprint":".+","role":".+","keyEpoch":\d+,"grantedAt":".+"\}$/,
        );
    });

    it('carries the schema version inside the signed bytes', () => {
        expect(JSON.parse(canonicaliseGrant(grant))).toMatchObject({ v: 1 });
    });

    it.each([
        ['vaultUuid', { vaultUuid: 'not-a-uuid' }],
        ['recipientUuid', { recipientUuid: '' }],
        ['an uppercase uuid', { vaultUuid: grant.vaultUuid.toUpperCase() }],
        ['a short fingerprint', { recipientFingerprint: 'ab' }],
        ['an uppercase fingerprint', { recipientFingerprint: 'A'.repeat(64) }],
        ['an unknown role', { role: 'admin' as Grant['role'] }],
        ['a zero epoch', { keyEpoch: 0 }],
        ['a fractional epoch', { keyEpoch: 1.5 }],
        ['a loose timestamp', { grantedAt: '2026-08-15 09:00:00' }],
        ['a millisecond timestamp', { grantedAt: '2026-08-15T09:00:00.000Z' }],
    ])('refuses to sign %s', (_label, override) => {
        expect(() => canonicaliseGrant({ ...grant, ...override })).toThrow(InvalidParameterError);
    });
});

describe('grantTimestamp', () => {
    it('renders to the second, in UTC', () => {
        expect(grantTimestamp(new Date('2026-08-15T09:00:00.123Z'))).toBe('2026-08-15T09:00:00Z');
    });

    it('is accepted by the canonicaliser it exists to feed', () => {
        expect(() => canonicaliseGrant({ ...grant, grantedAt: grantTimestamp() })).not.toThrow();
    });
});

describe('signGrant', () => {
    it('produces a 64-byte signature over the canonical payload', () => {
        expect(signed.signature).toHaveLength(64);
        expect(signed.payload).toBe(canonicaliseGrant(grant));
    });

    /**
     * A self-signature and a grant signature are both Ed25519 over bytes chosen
     * by us, made by the same key. Without a domain separator one could be
     * replayed as the other.
     */
    it('signs under a domain separator, so it cannot be replayed as another signature type', () => {
        const undecorated = ed25519.sign(utf8ToBytes(signed.payload), granter.ed25519.secretKey);

        expect(undecorated).not.toEqual(signed.signature);

        expect(
            ed25519.verify(
                signed.signature,
                concat(utf8ToBytes(GRANT_SIGNATURE_CONTEXT), utf8ToBytes('\0'), utf8ToBytes(signed.payload)),
                granter.ed25519.publicKey,
            ),
        ).toBe(true);
    });
});

describe('verifyGrant', () => {
    it('accepts a genuine grant that matches the membership offered', () => {
        const verdict = verify();

        expect(verdict.valid).toBe(true);
        expect(verdict.valid && verdict.grant.role).toBe('editor');
    });

    it('rejects a tampered signature', () => {
        const tampered = Uint8Array.from(signed.signature);
        // Non-null: a signature is 64 bytes, asserted above.
        tampered.set([tampered[0]! ^ 0x01], 0);

        const verdict = verifyGrant(tampered, signed.payload, granter.ed25519.publicKey, grant);

        expect(verdict).toMatchObject({ valid: false, reason: 'signature' });
    });

    it('rejects a payload edited after signing', () => {
        const edited = signed.payload.replace('"editor"', '"owner"');

        const verdict = verifyGrant(signed.signature, edited, granter.ed25519.publicKey, {
            ...grant,
            role: 'owner',
        });

        expect(verdict).toMatchObject({ valid: false, reason: 'signature' });
    });

    it('rejects a grant signed by somebody else', () => {
        const impostor = generateIdentity();

        const verdict = verifyGrant(signed.signature, signed.payload, impostor.ed25519.publicKey, grant);

        expect(verdict).toMatchObject({ valid: false, reason: 'signature' });
    });

    it.each([
        ['a signature of the wrong length', new Uint8Array(32), granter.ed25519.publicKey],
        ['a public key of the wrong length', signed.signature, new Uint8Array(16)],
    ])('rejects %s without attempting verification', (_label, signature, publicKey) => {
        expect(verifyGrant(signature, signed.payload, publicKey, grant)).toMatchObject({
            valid: false,
            reason: 'signature',
        });
    });

    /**
     * The whole point of passing the membership in. A signature proves the
     * granter signed *something*; only the comparison makes it evidence about
     * this row. A server holding any genuine grant could otherwise staple it to
     * a membership of its own devising.
     */
    it.each([
        ['a different vault', { vaultUuid: '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5aa' }],
        ['a different recipient', { recipientUuid: '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5bb' }],
        ['different recipient keys', { recipientFingerprint: 'b'.repeat(64) }],
        ['an elevated role', { role: 'owner' as Grant['role'] }],
        ['a different key epoch', { keyEpoch: 2 }],
    ])('rejects a valid signature stapled to %s', (_label, override) => {
        expect(verify(override)).toMatchObject({ valid: false, reason: 'mismatch' });
    });

    it('names the field that disagrees, so the warning can say what is wrong', () => {
        const verdict = verify({ role: 'owner' });

        expect(verdict.valid).toBe(false);
        expect(!verdict.valid && verdict.detail).toContain('editor');
    });

    /**
     * The granter's claim about when they acted, not something the row asserts.
     * Comparing it would turn clock skew into an attack report.
     */
    it('ignores the timestamp when comparing', () => {
        expect(verify({ grantedAt: '2020-01-01T00:00:00Z' }).valid).toBe(true);
    });

    it.each([
        ['not json at all', 'nonsense'],
        ['a json array', '[1,2,3]'],
        ['json null', 'null'],
        ['a bare string', '"grant"'],
        ['an unknown schema version', '{"v":2,"vaultUuid":"0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f6"}'],
        ['a grant with no version', '{"vaultUuid":"0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f6"}'],
    ])('reports %s as malformed rather than throwing', (_label, payload) => {
        expect(verifyGrant(signed.signature, payload, granter.ed25519.publicKey, grant)).toMatchObject({
            valid: false,
            reason: 'malformed',
        });
    });
});

describe('parseGrant', () => {
    const field = (overrides: Record<string, unknown>) => JSON.stringify({ v: 1, ...grant, ...overrides });

    it('round-trips a canonical grant', () => {
        expect(parseGrant(canonicaliseGrant(grant))).toEqual(grant);
    });

    it.each([
        ['a non-string vault uuid', { vaultUuid: 42 }],
        ['a malformed recipient uuid', { recipientUuid: 'nope' }],
        ['a non-string fingerprint', { recipientFingerprint: 1 }],
        ['a short fingerprint', { recipientFingerprint: 'ab' }],
        ['a non-string role', { role: 3 }],
        ['an unknown role', { role: 'superuser' }],
        ['a string epoch', { keyEpoch: '1' }],
        ['a fractional epoch', { keyEpoch: 1.5 }],
        ['a zero epoch', { keyEpoch: 0 }],
        ['a non-string timestamp', { grantedAt: 0 }],
        ['a malformed timestamp', { grantedAt: 'yesterday' }],
    ])('rejects %s', (_label, overrides) => {
        expect(parseGrant(field(overrides))).toBeNull();
    });

    /**
     * Deliberately not "re-canonicalise and compare strings". That would make
     * every signature invalid the day the serialisation changes, which is the
     * one thing storing the exact signed bytes exists to prevent. Safety comes
     * from the version check and from comparing every meaningful field against
     * the row.
     */
    it('tolerates an unknown field, because the bytes are what was signed', () => {
        expect(parseGrant(field({ note: 'added by a later version' }))).toEqual(grant);
    });
});

describe('fingerprintHex', () => {
    it('renders the full 256 bits in lowercase, as a grant records it', () => {
        const hex = fingerprintHex(generateIdentity().fingerprint);

        expect(hex).toHaveLength(64);
        expect(hex).toBe(hex.toLowerCase());
    });

    it('produces something canonicaliseGrant accepts', () => {
        const recipientFingerprint = fingerprintHex(generateIdentity().fingerprint);

        expect(() => canonicaliseGrant({ ...grant, recipientFingerprint })).not.toThrow();
    });
});
