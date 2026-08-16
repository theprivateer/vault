/**
 * `verifyRotation` documents that it never throws, because the certificate and
 * the retired public key both arrive from the server and are therefore
 * untrusted.
 *
 * The same situation as `grant.library-failure.test.ts`: today @noble/curves
 * returns false for malformed input rather than throwing, so the guarantee rests
 * on our own length checks and the catch block behind them is a defence against a
 * future change in the library. This keeps that defence honest rather than
 * leaving it as unreachable code nobody notices has stopped working.
 *
 * Its own file because the mock replaces the module for everything importing it.
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

const { canonicaliseRotation, verifyRotation } = await import('./rotation');

describe('verifyRotation when the curve library throws', () => {
    it('contains the error and reports the rotation as uncertified', () => {
        const statement = {
            userUuid: '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f6',
            previousFingerprint: 'a'.repeat(64),
            fingerprint: 'b'.repeat(64),
            rotatedAt: '2026-08-16T09:00:00Z',
        };

        const payload = canonicaliseRotation(statement);

        /*
         | Uncertified, not "certified anyway" and not a thrown exception. A
         | crash here would take down the page that is trying to warn somebody
         | their peer's keys changed — the single worst moment to fail open or
         | fail loud.
         */
        expect(
            verifyRotation(new Uint8Array(64), payload, new Uint8Array(32), {
                userUuid: statement.userUuid,
                previousFingerprint: statement.previousFingerprint,
                fingerprint: statement.fingerprint,
            }),
        ).toMatchObject({ certified: false, reason: 'signature' });
    });
});
