/**
 * The Phase 5 exit criteria that live in the browser.
 *
 * Two of them can only be tested here, because they are decisions no server is
 * involved in: a grant with a tampered signature must be rejected by the
 * recipient, and a substituted public key must produce a hard stop rather than a
 * silent accept. Both are exercised against real keys — a fixture that could not
 * actually verify would prove nothing about verification.
 *
 * The adversary throughout is the server. Every value passed in below is one it
 * supplies, so every test is really the same question asked five ways: what does
 * the client do when the server lies about this particular field?
 */
import { describe, expect, it } from 'vitest';

import { canonicaliseGrant, fingerprintHex, signGrant, type Grant } from '@/crypto/grant';
import { generateIdentity, signPublicKeys, type Identity } from '@/crypto/identity';

import { toBase64 } from './bytes';
import type { PinMap } from './pins';
import { checkIdentity, checkMembership, type MembershipRecord, type PublicIdentity } from './sharing';

const GRANTER_UUID = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f1';
const RECIPIENT_UUID = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f2';
const VAULT_UUID = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f3';
const MEMBERSHIP_UUID = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f4';

/** The bundle the identity endpoint would return for a real identity. */
function published(identity: Identity, uuid: string, handle = 'ada'): PublicIdentity {
    return {
        uuid,
        displayName: 'Ada',
        handle,
        x25519PublicKey: toBase64(identity.x25519.publicKey),
        ed25519PublicKey: toBase64(identity.ed25519.publicKey),
        selfSignature: toBase64(identity.selfSignature),
        fingerprint: toBase64(identity.fingerprint),
    };
}

const pinned = (uuid: string, identity: Identity): PinMap => ({
    [uuid]: fingerprintHex(identity.fingerprint),
});

describe('checkIdentity', () => {
    it('reports a well-formed identity that has never been seen as unverified', () => {
        const identity = generateIdentity();

        const check = checkIdentity(published(identity, GRANTER_UUID), {});

        expect(check.status).toBe('unverified');
        expect(check.fingerprint).toBe(fingerprintHex(identity.fingerprint));
    });

    it('reports a pinned identity as verified', () => {
        const identity = generateIdentity();

        expect(checkIdentity(published(identity, GRANTER_UUID), pinned(GRANTER_UUID, identity)).status).toBe(
            'verified',
        );
    });

    /**
     * The exit criterion, and the reason the pin store exists. A server that
     * swaps in its own keypair produces a bundle that is internally perfect —
     * valid self-signature, matching fingerprint — and is caught only by the
     * fact that it is not what was verified before.
     */
    it('hard-stops when the keys have changed since they were pinned', () => {
        const genuine = generateIdentity();
        const substituted = generateIdentity();

        const check = checkIdentity(published(substituted, GRANTER_UUID), pinned(GRANTER_UUID, genuine));

        expect(check.status).toBe('changed');
        expect(check.pinned).toBe(fingerprintHex(genuine.fingerprint));
        expect(check.fingerprint).toBe(fingerprintHex(substituted.fingerprint));
    });

    it('rejects a bundle whose self-signature does not verify', () => {
        const identity = generateIdentity();
        const impostor = generateIdentity();

        expect(
            checkIdentity(
                { ...published(identity, GRANTER_UUID), selfSignature: toBase64(impostor.selfSignature) },
                {},
            ).status,
        ).toBe('invalid');
    });

    /**
     * A self-signature over *someone else's* X25519 key. It verifies as a
     * signature — the granter really did sign those bytes — and it would let a
     * server pair a genuine Ed25519 identity with an X25519 key it controls,
     * which is the key that actually receives the sealed vault key.
     */
    it("rejects a bundle pairing one identity's signing key with another's encryption key", () => {
        const genuine = generateIdentity();
        const attacker = generateIdentity();

        const crossSigned = signPublicKeys(
            attacker.ed25519.secretKey,
            attacker.ed25519.publicKey,
            attacker.x25519.publicKey,
        );

        const check = checkIdentity(
            {
                ...published(genuine, GRANTER_UUID),
                // The attacker's X25519 key, and a signature that covers it.
                x25519PublicKey: toBase64(attacker.x25519.publicKey),
                selfSignature: toBase64(crossSigned),
            },
            pinned(GRANTER_UUID, genuine),
        );

        // The signature does not verify against the *published* Ed25519 key, so
        // this never reaches the pin comparison at all.
        expect(check.status).toBe('invalid');
    });

    /**
     * The fingerprint on the row is a cache, and the comparison is made against
     * a recomputed one. A server that published a fingerprint describing keys
     * other than the ones it sent is misdescribing its own data, which is not a
     * state to proceed through.
     */
    it('rejects a bundle whose published fingerprint does not match its keys', () => {
        const identity = generateIdentity();
        const other = generateIdentity();

        expect(
            checkIdentity(
                { ...published(identity, GRANTER_UUID), fingerprint: toBase64(other.fingerprint) },
                {},
            ).status,
        ).toBe('invalid');
    });

    it('rejects a bundle that is not even base64', () => {
        const identity = generateIdentity();

        expect(
            checkIdentity({ ...published(identity, GRANTER_UUID), x25519PublicKey: '!!!' }, {}).status,
        ).toBe('invalid');
    });

    it('rejects an all-zero key, which would verify against an all-zero signature', () => {
        const identity = generateIdentity();
        const zero = toBase64(new Uint8Array(32));

        expect(
            checkIdentity(
                {
                    ...published(identity, GRANTER_UUID),
                    ed25519PublicKey: zero,
                    selfSignature: toBase64(new Uint8Array(64)),
                },
                {},
            ).status,
        ).toBe('invalid');
    });
});

describe('checkMembership', () => {
    const granter = generateIdentity();
    const recipient = generateIdentity();

    const ownFingerprint = fingerprintHex(recipient.fingerprint);

    const grant: Grant = {
        vaultUuid: VAULT_UUID,
        recipientUuid: RECIPIENT_UUID,
        recipientFingerprint: ownFingerprint,
        role: 'editor',
        keyEpoch: 1,
        grantedAt: '2026-08-15T09:00:00Z',
    };

    const signed = signGrant(granter.ed25519.secretKey, grant);

    function membership(overrides: Partial<MembershipRecord> = {}): MembershipRecord {
        return {
            uuid: MEMBERSHIP_UUID,
            role: 'editor',
            keyEpoch: 1,
            acceptedAt: null,
            grantSignature: toBase64(signed.signature),
            grantPayload: signed.payload,
            grantedBy: published(granter, GRANTER_UUID),
            member: { uuid: RECIPIENT_UUID, displayName: 'Grace', handle: 'grace' },
            ...overrides,
        };
    }

    const pins = pinned(GRANTER_UUID, granter);

    it('trusts a genuine grant from a granter whose keys are pinned', () => {
        const trust = checkMembership(membership(), ownFingerprint, VAULT_UUID, pins);

        expect(trust.trusted).toBe(true);
        expect(trust.trusted && trust.grant.role).toBe('editor');
    });

    /** The exit criterion: a tampered signature is rejected by the recipient. */
    it('rejects a grant whose signature was tampered with', () => {
        const tampered = Uint8Array.from(signed.signature);
        // Non-null: a signature is 64 bytes.
        tampered.set([tampered[10]! ^ 0x40], 10);

        const trust = checkMembership(
            membership({ grantSignature: toBase64(tampered) }),
            ownFingerprint,
            VAULT_UUID,
            pins,
        );

        expect(trust).toMatchObject({ trusted: false, reason: 'grant' });
    });

    /**
     * A membership row is a write to a table the server owns. Without a
     * signature there is nothing distinguishing "someone shared this with you"
     * from "the server added a row", so this renders as a warning rather than as
     * a vault.
     */
    it('rejects a membership the server fabricated with no grant at all', () => {
        expect(
            checkMembership(
                membership({ grantSignature: null, grantPayload: null, grantedBy: null }),
                ownFingerprint,
                VAULT_UUID,
                pins,
            ),
        ).toMatchObject({ trusted: false, reason: 'unsigned' });
    });

    it('refuses to check a grant against a granter whose keys are not pinned', () => {
        expect(checkMembership(membership(), ownFingerprint, VAULT_UUID, {})).toMatchObject({
            trusted: false,
            reason: 'granter',
        });
    });

    it("refuses when the granter's keys have changed since they were pinned", () => {
        const substituted = generateIdentity();

        expect(
            checkMembership(
                membership({ grantedBy: published(substituted, GRANTER_UUID) }),
                ownFingerprint,
                VAULT_UUID,
                pins,
            ),
        ).toMatchObject({ trusted: false, reason: 'granter' });
    });

    /**
     * A genuine grant, stapled to a row that claims a different role. Only the
     * comparison against the row catches this — the signature verifies
     * perfectly, because it was never altered.
     */
    it('rejects a genuine grant attached to a row claiming a higher role', () => {
        expect(
            checkMembership(membership({ role: 'owner' }), ownFingerprint, VAULT_UUID, pins),
        ).toMatchObject({ trusted: false, reason: 'grant' });
    });

    it('rejects a genuine grant replayed against a different vault', () => {
        expect(
            checkMembership(membership(), ownFingerprint, '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5aa', pins),
        ).toMatchObject({ trusted: false, reason: 'grant' });
    });

    /**
     * The reason a grant names the recipient's fingerprint. A server that
     * substituted the recipient's own public key would hold a genuine grant
     * issued for keys that are no longer the ones in this browser.
     */
    it('rejects a grant issued for keys other than the ones this browser holds', () => {
        const replaced = generateIdentity();

        expect(
            checkMembership(membership(), fingerprintHex(replaced.fingerprint), VAULT_UUID, pins),
        ).toMatchObject({ trusted: false, reason: 'grant' });
    });

    it('rejects a grant carried over from a previous key epoch', () => {
        expect(checkMembership(membership({ keyEpoch: 2 }), ownFingerprint, VAULT_UUID, pins)).toMatchObject({
            trusted: false,
            reason: 'grant',
        });
    });

    it('rejects a signature that is not readable', () => {
        expect(
            checkMembership(membership({ grantSignature: '!!!' }), ownFingerprint, VAULT_UUID, pins),
        ).toMatchObject({ trusted: false, reason: 'grant' });
    });

    it('rejects a payload that was edited after signing', () => {
        const edited = canonicaliseGrant({ ...grant, role: 'owner' });

        expect(
            checkMembership(
                membership({ grantPayload: edited, role: 'owner' }),
                ownFingerprint,
                VAULT_UUID,
                pins,
            ),
        ).toMatchObject({ trusted: false, reason: 'grant' });
    });
});
