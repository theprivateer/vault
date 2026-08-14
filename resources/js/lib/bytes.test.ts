import { describe, expect, it } from 'vitest';

import { decodeUtf8, encodeUtf8, fromBase64, toBase64 } from './bytes';

describe('base64', () => {
    it('round trips arbitrary bytes', () => {
        for (const length of [0, 1, 2, 3, 31, 32, 64, 255]) {
            const bytes = crypto.getRandomValues(new Uint8Array(length));

            expect(fromBase64(toBase64(bytes))).toEqual(bytes);
        }
    });

    it('handles the full byte range, not just ASCII', () => {
        // Ciphertext is uniformly random, so a String.fromCharCode mistake would
        // show up on high bytes and nowhere else.
        const bytes = Uint8Array.from({ length: 256 }, (_value, index) => index);

        expect(fromBase64(toBase64(bytes))).toEqual(bytes);
    });

    it('produces standard padded base64', () => {
        expect(toBase64(Uint8Array.from([0x00]))).toBe('AA==');
        expect(toBase64(Uint8Array.from([0xff, 0xff, 0xff]))).toBe('////');
        expect(toBase64(new Uint8Array(0))).toBe('');
    });
});

describe('utf-8', () => {
    it('round trips', () => {
        const value = '{"key":"AWS root — production","value":"hunter2 🔐"}';

        expect(decodeUtf8(encodeUtf8(value))).toBe(value);
    });

    it('encodes multi-byte characters correctly', () => {
        expect(encodeUtf8('🔐')).toEqual(Uint8Array.from([0xf0, 0x9f, 0x94, 0x90]));
    });
});
