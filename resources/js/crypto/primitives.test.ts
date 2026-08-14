import { describe, expect, it } from 'vitest';

import { decodeBase32, encodeBase32, group } from './encoding';
import { InvalidParameterError } from './errors';
import { concat, deriveKey, randomBytes, stretchPassword, utf8ToBytes, zeroise } from './primitives';

const FAST_KDF = { m: 8, t: 1, p: 1 };

describe('randomBytes', () => {
    it('returns the requested length', () => {
        expect(randomBytes(1)).toHaveLength(1);
        expect(randomBytes(32)).toHaveLength(32);
        expect(randomBytes(1024)).toHaveLength(1024);
    });

    it('does not repeat', () => {
        const samples = Array.from({ length: 100 }, () => randomBytes(32).toString());

        expect(new Set(samples).size).toBe(100);
    });

    it.each([0, -1, 1.5, Number.NaN])('refuses a length of %p', (length) => {
        expect(() => randomBytes(length)).toThrow(InvalidParameterError);
    });
});

describe('stretchPassword', () => {
    const salt = randomBytes(16);

    it('returns 64 bytes', () => {
        expect(stretchPassword('password', salt, FAST_KDF)).toHaveLength(64);
    });

    it('is deterministic', () => {
        expect(stretchPassword('password', salt, FAST_KDF)).toEqual(
            stretchPassword('password', salt, FAST_KDF),
        );
    });

    it('refuses an empty password', () => {
        expect(() => stretchPassword('', salt, FAST_KDF)).toThrow(InvalidParameterError);
    });

    it('refuses a short salt', () => {
        expect(() => stretchPassword('password', randomBytes(15), FAST_KDF)).toThrow(InvalidParameterError);
    });

    it('uses the default parameters when none are given', () => {
        // Slow by design — one call at production cost, to prove the default
        // path works rather than only the fast test path. ~731 ms bare
        // (ADR-0003), several seconds under coverage instrumentation.
        expect(stretchPassword('password', salt)).toHaveLength(64);
    }, 30_000);
});

describe('deriveKey', () => {
    const input = randomBytes(32);
    const salt = randomBytes(16);

    it('is deterministic', () => {
        expect(deriveKey(input, salt, 'vault:test:v1')).toEqual(deriveKey(input, salt, 'vault:test:v1'));
    });

    it('is domain separated by info', () => {
        // Two keys derived from the same secret for different purposes must be
        // independent, or compromising one compromises the other.
        expect(deriveKey(input, salt, 'vault:a:v1')).not.toEqual(deriveKey(input, salt, 'vault:b:v1'));
    });

    it('is separated by salt', () => {
        expect(deriveKey(input, salt, 'vault:test:v1')).not.toEqual(
            deriveKey(input, randomBytes(16), 'vault:test:v1'),
        );
    });

    it('works without a salt', () => {
        expect(deriveKey(input, undefined, 'vault:test:v1')).toHaveLength(32);
    });

    it('honours a requested length', () => {
        expect(deriveKey(input, salt, 'vault:test:v1', 64)).toHaveLength(64);
    });
});

describe('helpers', () => {
    it('concatenates in order', () => {
        expect(concat(Uint8Array.from([1, 2]), Uint8Array.from([3]), Uint8Array.from([4, 5]))).toEqual(
            Uint8Array.from([1, 2, 3, 4, 5]),
        );
    });

    it('concatenates nothing into nothing', () => {
        expect(concat()).toEqual(new Uint8Array(0));
    });

    it('zeroises in place', () => {
        const a = randomBytes(32);
        const b = randomBytes(16);

        zeroise(a, b);

        expect(a.every((byte) => byte === 0)).toBe(true);
        expect(b.every((byte) => byte === 0)).toBe(true);
    });

    it('encodes UTF-8', () => {
        expect(utf8ToBytes('🔐')).toEqual(Uint8Array.from([0xf0, 0x9f, 0x94, 0x90]));
    });
});

describe('base32', () => {
    it('round trips arbitrary bytes', () => {
        for (const length of [1, 2, 5, 15, 16, 32]) {
            const bytes = randomBytes(length);

            expect(decodeBase32(encodeBase32(bytes))).toEqual(bytes);
        }
    });

    it('encodes to the Crockford alphabet only', () => {
        expect(encodeBase32(randomBytes(64))).toMatch(/^[0-9A-HJKMNP-TV-Z]+$/);
    });

    it('encodes an empty input to an empty string', () => {
        expect(encodeBase32(new Uint8Array(0))).toBe('');
        expect(decodeBase32('')).toEqual(new Uint8Array(0));
    });

    it('is case insensitive and ignores separators', () => {
        const bytes = randomBytes(16);
        const encoded = group(encodeBase32(bytes));

        expect(decodeBase32(encoded.toLowerCase())).toEqual(decodeBase32(encoded));
        expect(decodeBase32(encoded.replace(/-/g, ' '))).toEqual(decodeBase32(encoded));
    });

    it('rejects characters outside the alphabet', () => {
        expect(() => decodeBase32('ABC!')).toThrow(InvalidParameterError);
        expect(() => decodeBase32('ABCU')).toThrow(InvalidParameterError);
    });

    it('groups for printing', () => {
        expect(group('ABCDEFGHIJ')).toBe('ABCD-EFGH-IJ');
        expect(group('ABCDEF', 2, ' ')).toBe('AB CD EF');
        expect(group('')).toBe('');
    });
});
