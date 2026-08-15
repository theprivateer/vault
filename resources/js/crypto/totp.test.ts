/**
 * TOTP against the RFC's own vectors.
 *
 * The exit criterion for this phase is "codes match a reference authenticator
 * for a known seed", and the reference worth matching is RFC 6238's appendix B,
 * not another implementation — an agreement between two pieces of code written
 * from the same misunderstanding proves nothing. The vectors below are the
 * published ones, with the seed converted to base32 because that is the form
 * this application stores.
 */
import { describe, expect, it } from 'vitest';

import { InvalidParameterError } from './errors';
import {
    DEFAULT_TOTP,
    counterAt,
    decodeBase32,
    encodeBase32,
    generateTotpSecret,
    hotp,
    nowInSeconds,
    parseOtpauth,
    secondsRemaining,
    toOtpauth,
    totp,
    type TotpConfig,
} from './totp';

/** RFC 6238 appendix B: the ASCII string "12345678901234567890". */
const RFC_SHA1_SECRET = encodeBase32(new TextEncoder().encode('12345678901234567890'));

/** The SHA-256 vector uses a 32-byte seed: the same string, continued. */
const RFC_SHA256_SECRET = encodeBase32(new TextEncoder().encode('12345678901234567890123456789012'));

/** And SHA-512 a 64-byte one. */
const RFC_SHA512_SECRET = encodeBase32(
    new TextEncoder().encode('1234567890123456789012345678901234567890123456789012345678901234'),
);

function config(overrides: Partial<TotpConfig> = {}): TotpConfig {
    return { ...DEFAULT_TOTP, secret: RFC_SHA1_SECRET, digits: 8, ...overrides };
}

describe('RFC 6238 test vectors', () => {
    /*
     | The published table, verbatim. Eight digits because that is what the RFC
     | tabulates; six-digit codes are the same computation truncated further,
     | which the case below pins separately.
     */
    it.each([
        [59, '94287082'],
        [1111111109, '07081804'],
        [1111111111, '14050471'],
        [1234567890, '89005924'],
        [2000000000, '69279037'],
        [20000000000, '65353130'],
    ])('produces the SHA-1 code at t=%i', (time, expected) => {
        expect(totp(config(), time)).toBe(expected);
    });

    it.each([
        [59, '46119246'],
        [1111111109, '68084774'],
        [2000000000, '90698825'],
    ])('produces the SHA-256 code at t=%i', (time, expected) => {
        expect(totp(config({ secret: RFC_SHA256_SECRET, algorithm: 'SHA256' }), time)).toBe(expected);
    });

    it.each([
        [59, '90693936'],
        [1111111109, '25091201'],
        [2000000000, '38618901'],
    ])('produces the SHA-512 code at t=%i', (time, expected) => {
        expect(totp(config({ secret: RFC_SHA512_SECRET, algorithm: 'SHA512' }), time)).toBe(expected);
    });

    /*
     | The shape every authenticator app actually shows. Six digits is the last
     | six of the eight above, which is what dynamic truncation modulo 10^6
     | gives — a useful check that `digits` is applied at the end rather than
     | changing the truncation.
     */
    it('truncates to six digits without changing the underlying value', () => {
        expect(totp(config({ digits: 6 }), 59)).toBe('287082');
        expect(totp(config({ digits: 6 }), 1111111109)).toBe('081804');
    });
});

describe('base32', () => {
    it('round-trips arbitrary bytes', () => {
        const bytes = Uint8Array.from({ length: 20 }, (_, at) => (at * 37) % 256);

        expect(decodeBase32(encodeBase32(bytes))).toEqual(bytes);
    });

    /*
     | What people actually paste. Setup pages print seeds in lower case, in
     | groups of four, and sometimes with padding — a generator that refused any
     | of those would look broken for a reason nobody could see.
     */
    it('accepts the spacing, case and padding a setup page produces', () => {
        const canonical = 'JBSWY3DPEHPK3PXP';

        expect(decodeBase32('jbswy3dp ehpk3pxp')).toEqual(decodeBase32(canonical));
        expect(decodeBase32('JBSW-Y3DP-EHPK-3PXP')).toEqual(decodeBase32(canonical));
        expect(decodeBase32('JBSWY3DPEHPK3PXP===')).toEqual(decodeBase32(canonical));
    });

    /*
     | A character outside the alphabet is a mistyped seed. Skipping it would
     | silently produce a *different* key and therefore codes that are wrong
     | every single time, with nothing on screen to explain why.
     */
    it('refuses a character that is not base32 rather than dropping it', () => {
        expect(() => decodeBase32('JBSW1YDP')).toThrow(InvalidParameterError);
        expect(() => decodeBase32('')).toThrow(InvalidParameterError);
        expect(() => decodeBase32('=')).toThrow(InvalidParameterError);

        // A single character is five bits: well formed, and not enough to make
        // even one byte of key. Distinct from the empty case above, and worth
        // its own message rather than returning a zero-length key.
        expect(() => decodeBase32('A')).toThrow(/too short/);
    });

    it('generates a 160-bit seed', () => {
        const secret = generateTotpSecret((length) => new Uint8Array(length).fill(7));

        expect(decodeBase32(secret)).toHaveLength(20);
    });
});

describe('the clock', () => {
    it('counts periods from the epoch', () => {
        expect(counterAt(0)).toBe(0);
        expect(counterAt(29)).toBe(0);
        expect(counterAt(30)).toBe(1);
        expect(counterAt(59, 30)).toBe(1);
    });

    it('reports the seconds left in the current code', () => {
        expect(secondsRemaining(0)).toBe(30);
        expect(secondsRemaining(1)).toBe(29);
        expect(secondsRemaining(29.5)).toBe(1);
        expect(secondsRemaining(30)).toBe(30);
    });

    it('honours a non-default period', () => {
        expect(counterAt(120, 60)).toBe(2);
        expect(secondsRemaining(70, 60)).toBe(50);
    });

    it('refuses a nonsensical clock or period', () => {
        expect(() => counterAt(-1)).toThrow(InvalidParameterError);
        expect(() => counterAt(Number.NaN)).toThrow(InvalidParameterError);
        expect(() => counterAt(0, 0)).toThrow(InvalidParameterError);
    });

    it('reads the wall clock in seconds', () => {
        expect(nowInSeconds()).toBeCloseTo(Date.now() / 1000, 1);
    });
});

describe('otpauth:// URIs', () => {
    it('reads the form a QR code encodes', () => {
        const parsed = parseOtpauth(
            'otpauth://totp/Example:phil@example.test?secret=JBSWY3DPEHPK3PXP&issuer=Example' +
                '&algorithm=SHA256&digits=8&period=60',
        );

        expect(parsed).toEqual({
            secret: 'JBSWY3DPEHPK3PXP',
            algorithm: 'SHA256',
            digits: 8,
            period: 60,
            label: 'Example:phil@example.test',
            issuer: 'Example',
        });
    });

    /*
     | Both label and issuer are display-only and genuinely optional. Omitting
     | them beats storing empty strings, which would render as a blank issuer in
     | the interface and read as a bug.
     */
    it('omits an absent label and issuer rather than storing empty ones', () => {
        const parsed = parseOtpauth('otpauth://totp/?secret=JBSWY3DPEHPK3PXP');

        expect(parsed).toEqual({
            secret: 'JBSWY3DPEHPK3PXP',
            algorithm: 'SHA1',
            digits: 6,
            period: 30,
        });
    });

    it('falls back to the defaults every authenticator assumes', () => {
        const parsed = parseOtpauth('otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP');

        expect(parsed.algorithm).toBe('SHA1');
        expect(parsed.digits).toBe(6);
        expect(parsed.period).toBe(30);
    });

    /*
     | An hotp credential would need a counter that this application does not
     | keep, so it would produce one valid code and then silently produce wrong
     | ones forever. Refusing it at the point of paste is the only moment anyone
     | could understand the message.
     */
    it('refuses a counter-based credential', () => {
        expect(() => parseOtpauth('otpauth://hotp/Example?secret=JBSWY3DPEHPK3PXP&counter=1')).toThrow(
            /counter-based/,
        );
    });

    it('refuses a URI that is malformed, foreign, or carries no secret', () => {
        expect(() => parseOtpauth('not a uri')).toThrow(InvalidParameterError);
        expect(() => parseOtpauth('https://example.test/?secret=JBSWY3DPEHPK3PXP')).toThrow(/otpauth/);
        expect(() => parseOtpauth('otpauth://totp/Example')).toThrow(/no secret/);
    });

    /*
     | Validated at the point of paste rather than at the first code. A seed that
     | only fails thirty seconds later, on a screen that has moved on, is a seed
     | nobody connects to what they typed.
     */
    it('rejects a bad seed while the user is still looking at the field', () => {
        expect(() => parseOtpauth('otpauth://totp/Example?secret=NOT!BASE32')).toThrow(InvalidParameterError);
    });

    it('refuses an algorithm or size it cannot honour', () => {
        expect(() => parseOtpauth('otpauth://totp/E?secret=JBSWY3DP&algorithm=MD5')).toThrow(
            /Unsupported TOTP algorithm/,
        );
        expect(() => parseOtpauth('otpauth://totp/E?secret=JBSWY3DP&digits=4')).toThrow(/digits/);
        expect(() => parseOtpauth('otpauth://totp/E?secret=JBSWY3DP&period=0')).toThrow(/period/);
    });

    it('writes a URI a phone can read back', () => {
        const uri = toOtpauth(config({ digits: 6 }), 'phil@example.test', 'Vault');
        const parsed = parseOtpauth(uri);

        expect(parsed.secret).toBe(RFC_SHA1_SECRET);
        expect(parsed.digits).toBe(6);
        expect(parsed.issuer).toBe('Vault');
    });
});

describe('refusing to produce a wrong code', () => {
    it('rejects a configuration it cannot honour', () => {
        expect(() => hotp({ ...config(), algorithm: 'MD5' as 'SHA1' }, 1)).toThrow(InvalidParameterError);
        expect(() => hotp(config({ digits: 4 }), 1)).toThrow(InvalidParameterError);
        expect(() => hotp(config({ period: 0 }), 1)).toThrow(InvalidParameterError);
        expect(() => hotp(config(), -1)).toThrow(InvalidParameterError);
    });

    /*
     | The counter is written as a 64-bit big-endian integer, assembled from a
     | double rather than a BigInt. This pins the assembly at a counter large
     | enough to occupy more than one byte, which is where an endianness or
     | carry mistake would show up.
     */
    it('encodes a large counter correctly', () => {
        expect(hotp(config(), 666666666)).toBe(totp(config(), 666666666 * 30));
    });
});
