import { describe, expect, it } from 'vitest';

import {
    AUDIT_ACTIONS,
    AUDIT_SIGNATURE_CONTEXT,
    AUDIT_VERSION,
    auditTimestamp,
    canonicaliseStatement,
    signAuditStatement,
    verifyAuditStatement,
    type AuditActionName,
    type AuditStatement,
} from './audit';
import { InvalidParameterError } from './errors';
import { GRANT_SIGNATURE_CONTEXT, signGrant } from './grant';
import { generateIdentity } from './identity';

const SUBJECT = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f6';
const OTHER = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f7';

const statement = (overrides: Partial<AuditStatement> = {}): AuditStatement => ({
    action: 'secret.revealed',
    subjectUuid: SUBJECT,
    at: '2026-08-15T09:00:00Z',
    ...overrides,
});

describe('canonical form', () => {
    it('is the documented field order', () => {
        expect(canonicaliseStatement(statement())).toBe(
            `{"v":${AUDIT_VERSION},"action":"secret.revealed","subjectUuid":"${SUBJECT}","at":"2026-08-15T09:00:00Z"}`,
        );
    });

    /*
     | Field order is fixed rather than left to literal order, because the bytes
     | are what the signature commits to. Two clients that disagreed about the
     | order would produce signatures neither could verify.
     */
    it('does not depend on the order the object was built in', () => {
        const built: AuditStatement = {
            at: '2026-08-15T09:00:00Z',
            subjectUuid: SUBJECT,
            action: 'vault.unlocked',
        };

        expect(canonicaliseStatement(built)).toBe(
            canonicaliseStatement({
                action: 'vault.unlocked',
                subjectUuid: SUBJECT,
                at: '2026-08-15T09:00:00Z',
            }),
        );
    });

    it.each(AUDIT_ACTIONS)('accepts the declared action %s', (action) => {
        expect(() => canonicaliseStatement(statement({ action }))).not.toThrow();
    });

    /*
     | The closed set is a signing oracle by another name: whatever is in it is
     | something injected script can obtain this key's signature on. A
     | server-observed action has no business here — the server watched it
     | happen and does not need the browser's word for it.
     */
    it('refuses an action outside the closed set', () => {
        expect(() =>
            canonicaliseStatement(statement({ action: 'vault.deleted' as AuditActionName })),
        ).toThrow(InvalidParameterError);
    });

    it.each([
        ['not-a-uuid', 'a bare string'],
        ['0192F3A1-4B2C-7D3E-8F90-A1B2C3D4E5F6', 'uppercase'],
        ['../../../etc/passwd', 'a traversal attempt'],
    ])('refuses the subject %s (%s)', (subjectUuid) => {
        expect(() => canonicaliseStatement(statement({ subjectUuid }))).toThrow(InvalidParameterError);
    });

    it.each(['2026-08-15 09:00:00', '2026-08-15T09:00:00.000Z', '2026-08-15T09:00:00+01:00', 'yesterday'])(
        'refuses the timestamp %s',
        (at) => {
            expect(() => canonicaliseStatement(statement({ at }))).toThrow(InvalidParameterError);
        },
    );
});

describe('timestamps', () => {
    it('renders UTC to the second, with no fractional part', () => {
        expect(auditTimestamp(new Date('2026-08-15T09:00:00.512Z'))).toBe('2026-08-15T09:00:00Z');
    });

    it('produces a value its own canonicaliser accepts', () => {
        expect(() => canonicaliseStatement(statement({ at: auditTimestamp() }))).not.toThrow();
    });
});

describe('signing', () => {
    it('round-trips against the public half of the same identity', () => {
        const identity = generateIdentity();
        const { payload, signature } = signAuditStatement(identity.ed25519.secretKey, statement());

        expect(verifyAuditStatement(signature, payload, identity.ed25519.publicKey)).toBe(true);
    });

    it('does not verify against a different key', () => {
        const identity = generateIdentity();
        const stranger = generateIdentity();
        const { payload, signature } = signAuditStatement(identity.ed25519.secretKey, statement());

        expect(verifyAuditStatement(signature, payload, stranger.ed25519.publicKey)).toBe(false);
    });

    /*
     | The comparison the server also makes. A signature proves this key signed
     | *some* statement; it says nothing about which one, so a genuine signature
     | over one secret must not verify against a payload naming another.
     */
    it('does not verify against a payload it was not made over', () => {
        const identity = generateIdentity();
        const { signature } = signAuditStatement(identity.ed25519.secretKey, statement());
        const other = canonicaliseStatement(statement({ subjectUuid: OTHER }));

        expect(verifyAuditStatement(signature, other, identity.ed25519.publicKey)).toBe(false);
    });

    /**
     * Domain separation, which is the reason both contexts exist.
     *
     * A self-signature, a grant and an audit statement are all Ed25519
     * signatures by one key. Without a separator, a signature over one could be
     * presented as another — and a grant is a statement about *access*, which
     * would be a considerably worse thing to have replayed.
     */
    it('cannot be confused with a grant signed by the same key', () => {
        const identity = generateIdentity();

        const grant = signGrant(identity.ed25519.secretKey, {
            vaultUuid: SUBJECT,
            recipientUuid: OTHER,
            recipientFingerprint: 'a'.repeat(64),
            role: 'viewer',
            keyEpoch: 1,
            grantedAt: '2026-08-15T09:00:00Z',
        });

        // The grant's signature, offered as an audit statement's.
        expect(verifyAuditStatement(grant.signature, grant.payload, identity.ed25519.publicKey)).toBe(false);
        expect(AUDIT_SIGNATURE_CONTEXT).not.toBe(GRANT_SIGNATURE_CONTEXT);
    });

    it('reports a malformed key as a failure rather than throwing', () => {
        const identity = generateIdentity();
        const { payload, signature } = signAuditStatement(identity.ed25519.secretKey, statement());

        // Untrusted input renders as a warning, never an exception — the same
        // asymmetry as verifyGrant.
        expect(verifyAuditStatement(signature, payload, new Uint8Array(7))).toBe(false);
        expect(verifyAuditStatement(new Uint8Array(7), payload, identity.ed25519.publicKey)).toBe(false);
    });

    it('refuses to sign a statement it would not canonicalise', () => {
        const identity = generateIdentity();

        expect(() =>
            signAuditStatement(identity.ed25519.secretKey, statement({ subjectUuid: 'nope' })),
        ).toThrow(InvalidParameterError);
    });
});
