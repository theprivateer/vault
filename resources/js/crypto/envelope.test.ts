import { describe, expect, it } from 'vitest';

import type { AadParams } from './aad';
import { ALG_XCHACHA20_POLY1305, ENVELOPE_VERSION, MIN_ENVELOPE_LENGTH, open, seal } from './envelope';
import {
    IntegrityError,
    InvalidParameterError,
    MalformedEnvelopeError,
    UnsupportedEnvelopeError,
} from './errors';
import { KEY_LENGTH, randomBytes, utf8ToBytes } from './primitives';

const SUBJECT = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f6';
const OTHER_SUBJECT = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f7';

const aad: AadParams = { context: 'secret.payload', subject: SUBJECT, version: 1 };

const key = () => randomBytes(KEY_LENGTH);

describe('round trip', () => {
    it.each([0, 1, 15, 16, 17, 32, 1000, 65_536])('survives a %i byte plaintext', (size) => {
        const k = key();
        const plaintext = size === 0 ? new Uint8Array(0) : randomBytes(size);

        expect(open(k, seal(k, plaintext, aad), aad)).toEqual(plaintext);
    });

    it('preserves exact bytes, including a UTF-8 payload', () => {
        const k = key();
        const plaintext = utf8ToBytes('{"key":"AWS root — production","value":"hunter2 🔐"}');

        expect(open(k, seal(k, plaintext, aad), aad)).toEqual(plaintext);
    });
});

describe('envelope structure', () => {
    it('carries the version and algorithm in its first two bytes', () => {
        const envelope = seal(key(), utf8ToBytes('x'), aad);

        expect(envelope[0]).toBe(ENVELOPE_VERSION);
        expect(envelope[1]).toBe(ALG_XCHACHA20_POLY1305);
    });

    it('costs a fixed overhead over the plaintext', () => {
        expect(seal(key(), new Uint8Array(0), aad)).toHaveLength(MIN_ENVELOPE_LENGTH);
        expect(seal(key(), new Uint8Array(100), aad)).toHaveLength(MIN_ENVELOPE_LENGTH + 100);
    });

    it('uses a fresh nonce for every seal', () => {
        const k = key();
        const plaintext = utf8ToBytes('identical plaintext');

        const envelopes = Array.from({ length: 50 }, () => seal(k, plaintext, aad));
        const nonces = new Set(envelopes.map((e) => e.subarray(2, 26).toString()));

        // Identical plaintext under an identical key must never produce
        // identical ciphertext.
        expect(nonces.size).toBe(50);
        expect(new Set(envelopes.map((e) => e.toString())).size).toBe(50);
    });
});

describe('tamper detection', () => {
    /*
     | The exhaustive one. Every bit of a sealed envelope is flipped in turn and
     | each must be rejected. Header bits produce an UnsupportedEnvelopeError
     | (0x01 flips to no other valid identifier); everything downstream of the
     | header fails the Poly1305 tag.
     */
    it('rejects every single-bit mutation', () => {
        const k = key();
        const envelope = seal(k, utf8ToBytes('tamper me'), aad);

        for (let byte = 0; byte < envelope.length; byte++) {
            for (let bit = 0; bit < 8; bit++) {
                const mutated = Uint8Array.from(envelope);
                mutated[byte] = mutated[byte]! ^ (1 << bit);

                const expected = byte < 2 ? UnsupportedEnvelopeError : IntegrityError;

                expect(() => open(k, mutated, aad), `byte ${byte} bit ${bit} was accepted`).toThrow(expected);
            }
        }
    });

    it('rejects a truncated envelope', () => {
        const k = key();
        const envelope = seal(k, utf8ToBytes('a longer plaintext to truncate'), aad);

        expect(() => open(k, envelope.subarray(0, envelope.length - 1), aad)).toThrow(IntegrityError);
        expect(() => open(k, envelope.subarray(0, MIN_ENVELOPE_LENGTH), aad)).toThrow(IntegrityError);
        expect(() => open(k, envelope.subarray(0, MIN_ENVELOPE_LENGTH - 1), aad)).toThrow(
            MalformedEnvelopeError,
        );
    });

    it('rejects an extended envelope', () => {
        const k = key();
        const envelope = seal(k, utf8ToBytes('append to me'), aad);
        const extended = new Uint8Array(envelope.length + 1);
        extended.set(envelope);

        expect(() => open(k, extended, aad)).toThrow(IntegrityError);
    });

    it('rejects a swapped nonce', () => {
        const k = key();
        const a = seal(k, utf8ToBytes('first'), aad);
        const b = seal(k, utf8ToBytes('second'), aad);

        b.set(a.subarray(2, 26), 2);

        expect(() => open(k, b, aad)).toThrow(IntegrityError);
    });

    it('rejects the wrong key', () => {
        expect(() => open(key(), seal(key(), utf8ToBytes('secret'), aad), aad)).toThrow(IntegrityError);
    });
});

describe('associated data binding', () => {
    /*
     | SR4. Without AAD binding a malicious server can relocate a ciphertext to a
     | different record or field and the client decrypts it happily.
     */
    it('refuses a ciphertext moved to another record', () => {
        const k = key();
        const envelope = seal(k, utf8ToBytes('vault A secret'), aad);

        expect(() => open(k, envelope, { ...aad, subject: OTHER_SUBJECT })).toThrow(IntegrityError);
    });

    it('refuses a ciphertext moved to another field', () => {
        const k = key();
        const envelope = seal(k, utf8ToBytes('an item key'), { ...aad, context: 'item.key' });

        expect(() => open(k, envelope, { ...aad, context: 'vault.membership.key' })).toThrow(IntegrityError);
    });

    it('refuses a ciphertext replayed at a different payload version', () => {
        const k = key();
        const envelope = seal(k, utf8ToBytes('v1 payload'), { ...aad, version: 1 });

        expect(() => open(k, envelope, { ...aad, version: 2 })).toThrow(IntegrityError);
    });

    it('names the record in the error, so the UI can be specific', () => {
        const k = key();

        try {
            open(k, seal(k, utf8ToBytes('x'), aad), { ...aad, subject: OTHER_SUBJECT });
            expect.unreachable('tampered envelope was accepted');
        } catch (error) {
            expect(error).toBeInstanceOf(IntegrityError);
            expect((error as IntegrityError).subject).toBe(OTHER_SUBJECT);
            expect((error as IntegrityError).context).toBe('secret.payload');
        }
    });
});

describe('rejected inputs', () => {
    it.each([
        [0, 'empty'],
        [16, 'too short'],
        [31, 'one byte short'],
        [33, 'one byte long'],
        [64, 'too long'],
    ])('refuses a %i byte key (%s)', (length) => {
        const badKey = length === 0 ? new Uint8Array(0) : randomBytes(length);

        expect(() => seal(badKey, utf8ToBytes('x'), aad)).toThrow(InvalidParameterError);
        expect(() => open(badKey, new Uint8Array(MIN_ENVELOPE_LENGTH), aad)).toThrow(InvalidParameterError);
    });

    it('refuses an envelope shorter than the minimum', () => {
        expect(() => open(key(), new Uint8Array(MIN_ENVELOPE_LENGTH - 1), aad)).toThrow(
            MalformedEnvelopeError,
        );
    });

    it.each([
        [0, ALG_XCHACHA20_POLY1305],
        [2, ALG_XCHACHA20_POLY1305],
        [ENVELOPE_VERSION, 0],
        [ENVELOPE_VERSION, 2],
        [99, 99],
    ])('refuses version %i algorithm %i rather than guessing', (version, algorithm) => {
        const k = key();
        const envelope = seal(k, utf8ToBytes('x'), aad);
        envelope[0] = version;
        envelope[1] = algorithm;

        expect(() => open(k, envelope, aad)).toThrow(UnsupportedEnvelopeError);
    });

    it('surfaces a malformed AAD as a programming error, not a tamper', () => {
        const k = key();
        const envelope = seal(k, utf8ToBytes('x'), aad);

        // A caller mistake must not be disguised as an integrity failure, or a
        // real attack becomes indistinguishable from a bug.
        expect(() => open(k, envelope, { ...aad, subject: 'not-a-uuid' })).toThrow(InvalidParameterError);
    });
});
