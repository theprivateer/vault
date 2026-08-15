/**
 * `verifyGrant` documents that it never throws, because a grant and its
 * signature both arrive from the server and are therefore untrusted.
 *
 * As with `verifyPublicKeys`, the current @noble/curves returns false for every
 * malformed input rather than throwing, so today that guarantee rests on our own
 * length checks. The catch block behind it defends against a future change in
 * the library, and this file keeps that defence honest rather than leaving it as
 * unreachable code that nobody notices has stopped working.
 *
 * Its own file for the same reason as identity.library-failure.test.ts: the mock
 * replaces the module for everything that imports it.
 */
import { describe, expect, it, vi } from 'vitest';

vi.mock('@noble/curves/ed25519.js', async (importOriginal) => {
    const actual = await importOriginal<typeof import('@noble/curves/ed25519.js')>();

    return {
        ...actual,
        ed25519: {
            ...actual.ed25519,
            verify: () => {
                throw new Error('simulated library failure');
            },
        },
    };
});

const { canonicaliseGrant, verifyGrant } = await import('./grant');

describe('verifyGrant when the curve library throws', () => {
    it('contains the error and reports the grant as unsigned rather than crashing the page', () => {
        const grant = {
            vaultUuid: '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f6',
            recipientUuid: '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f7',
            recipientFingerprint: 'a'.repeat(64),
            role: 'viewer' as const,
            keyEpoch: 1,
            grantedAt: '2026-08-15T09:00:00Z',
        };

        // Both correctly sized, so the length checks pass and the call reaches
        // the mocked verify.
        const verdict = verifyGrant(
            new Uint8Array(64).fill(0x03),
            canonicaliseGrant(grant),
            new Uint8Array(32).fill(0x02),
            grant,
        );

        expect(verdict).toMatchObject({ valid: false, reason: 'signature' });
    });
});
