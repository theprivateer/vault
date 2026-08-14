/**
 * `verifyPublicKeys` documents that it never throws, because everything it
 * receives comes from the server and is therefore untrusted.
 *
 * The current @noble/curves returns false for every malformed input rather than
 * throwing, so that guarantee currently rests on our own validation. The catch
 * block behind it is defence against a future change in the library's
 * behaviour — and this file keeps that defence honest rather than letting it
 * rot as unreachable, untested code.
 *
 * It lives in its own file because the mock replaces the module for everything
 * that imports it.
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

const { verifyPublicKeys } = await import('./identity');

describe('verifyPublicKeys when the curve library throws', () => {
    it('contains the error and reports the identity as unverified', () => {
        // Structurally valid and not small order, so validation passes and the
        // call reaches the mocked verify.
        const signature = new Uint8Array(64).fill(0x03);
        const ed25519PublicKey = new Uint8Array(32).fill(0x02);
        const x25519PublicKey = new Uint8Array(32).fill(0x04);

        expect(verifyPublicKeys(signature, ed25519PublicKey, x25519PublicKey)).toBe(false);
    });
});
