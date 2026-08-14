/**
 * Proves the Vitest harness runs and that WebCrypto is available in the test
 * environment, which everything in Phase 1 depends on.
 *
 * Delete this once resources/js/crypto has real tests.
 */
import { describe, expect, it } from 'vitest';

describe('test harness', () => {
    it('runs', () => {
        expect(true).toBe(true);
    });

    it('exposes a CSPRNG', () => {
        const bytes = crypto.getRandomValues(new Uint8Array(32));

        expect(bytes).toHaveLength(32);
        expect(bytes.every((byte) => byte === 0)).toBe(false);
    });
});
