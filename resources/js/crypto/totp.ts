/**
 * Time-based one-time passwords, in the browser (RFC 6238 over RFC 4226).
 *
 * There is a second TOTP implementation in this project, `App\Support\Totp`, and
 * the two are not redundant — they protect different things and one of them
 * could not do the other's job:
 *
 *  - The PHP one guards *authentication*. The server holds that seed, checks
 *    the code, and issues a session.
 *  - This one guards nothing. It is a stored credential like any other: the
 *    seed lives inside `payload_ct`, the server has never seen it, and this
 *    module turns it into the six digits a user would otherwise read off their
 *    phone. Moving it server-side would mean handing over a seed that is worth
 *    exactly as much as the password beside it.
 *
 * Both are about thirty lines of well-specified arithmetic, which is why neither
 * is a dependency (A10).
 *
 * The primitive is HMAC-SHA1 by specification, not by choice. SHA-1's collision
 * weaknesses do not apply to HMAC, and every authenticator app in existence
 * expects it; `algorithm` exists because the `otpauth://` scheme permits SHA-256
 * and SHA-512 and a few issuers use them.
 */
import { hmac } from '@noble/hashes/hmac.js';
import { sha1 } from '@noble/hashes/legacy.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';

import { InvalidParameterError } from './errors';

/** RFC 4648 base32, which is the alphabet authenticator apps speak. */
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export const DEFAULT_DIGITS = 6;

export const DEFAULT_PERIOD = 30;

/**
 * The hashes `otpauth://` allows.
 *
 * A closed set, as everywhere else here: an unrecognised algorithm must fail
 * loudly rather than silently falling back to SHA-1, because a code generated
 * under the wrong hash is simply wrong and the only symptom is a login that
 * does not work.
 */
export const TOTP_ALGORITHMS = ['SHA1', 'SHA256', 'SHA512'] as const;

export type TotpAlgorithm = (typeof TOTP_ALGORITHMS)[number];

const HASHES = { SHA1: sha1, SHA256: sha256, SHA512: sha512 } as const;

/** Everything needed to produce a code, as an `otpauth://` URI describes it. */
export interface TotpConfig {
    /** Base32, unpadded, as stored inside the secret's payload. */
    secret: string;
    algorithm: TotpAlgorithm;
    digits: number;
    period: number;
    /** Display only: the account an authenticator app would show. */
    label?: string;
    issuer?: string;
}

export const DEFAULT_TOTP: Omit<TotpConfig, 'secret'> = {
    algorithm: 'SHA1',
    digits: DEFAULT_DIGITS,
    period: DEFAULT_PERIOD,
};

/**
 * Decodes unpadded base32.
 *
 * Tolerant of the spacing and lower case that people paste out of a setup page,
 * and strict about everything else: a character outside the alphabet is a
 * mistyped seed, and a seed that silently loses a character produces codes that
 * are wrong in a way nothing explains.
 */
export function decodeBase32(value: string): Uint8Array {
    const cleaned = value.replace(/[\s-]/g, '').replace(/=+$/, '').toUpperCase();

    if (cleaned === '') {
        throw new InvalidParameterError('A TOTP secret cannot be empty.');
    }

    let bits = 0;
    let accumulator = 0;
    const bytes: number[] = [];

    for (const character of cleaned) {
        const index = ALPHABET.indexOf(character);

        if (index === -1) {
            throw new InvalidParameterError(
                `“${character}” is not a base32 character. A TOTP secret uses A–Z and 2–7 only.`,
            );
        }

        accumulator = (accumulator << 5) | index;
        bits += 5;

        if (bits >= 8) {
            bits -= 8;
            bytes.push((accumulator >> bits) & 0xff);
        }
    }

    if (bytes.length === 0) {
        throw new InvalidParameterError('That TOTP secret is too short to contain any key material.');
    }

    return Uint8Array.from(bytes);
}

/** Encodes bytes as unpadded base32, for generating a new seed. */
export function encodeBase32(bytes: Uint8Array): string {
    let bits = 0;
    let accumulator = 0;
    let output = '';

    for (const byte of bytes) {
        accumulator = (accumulator << 8) | byte;
        bits += 8;

        while (bits >= 5) {
            bits -= 5;
            output += ALPHABET[(accumulator >> bits) & 0x1f];
        }
    }

    if (bits > 0) {
        output += ALPHABET[(accumulator << (5 - bits)) & 0x1f];
    }

    return output;
}

/**
 * The counter for a moment in time, which is the only place the clock enters.
 *
 * Separated out so that everything below is a pure function of a counter, and
 * the tests can pin an RFC vector to an exact instant rather than mocking time.
 */
export function counterAt(secondsSinceEpoch: number, period: number = DEFAULT_PERIOD): number {
    if (!Number.isFinite(secondsSinceEpoch) || secondsSinceEpoch < 0) {
        throw new InvalidParameterError(`A TOTP timestamp must be a positive number of seconds.`);
    }

    if (!Number.isSafeInteger(period) || period < 1) {
        throw new InvalidParameterError(`A TOTP period must be a positive whole number of seconds.`);
    }

    return Math.floor(secondsSinceEpoch / period);
}

/**
 * One HOTP code (RFC 4226 §5.3), which is what a TOTP code actually is.
 *
 * The counter is written as a 64-bit big-endian integer. It is assembled a byte
 * at a time from a `Number` rather than through a `BigInt` because the value is
 * seconds-since-epoch divided by thirty — around 5.8 × 10⁷ today, and safe as a
 * double until long after this code is gone.
 */
export function hotp(config: TotpConfig, counter: number): string {
    assertConfig(config);

    if (!Number.isSafeInteger(counter) || counter < 0) {
        throw new InvalidParameterError('A TOTP counter must be a non-negative integer.');
    }

    const message = new Uint8Array(8);

    for (let index = 7, remaining = counter; index >= 0; index--) {
        message[index] = remaining % 256;
        remaining = Math.floor(remaining / 256);
    }

    const digest = hmac(HASHES[config.algorithm], decodeBase32(config.secret), message);

    // Dynamic truncation, RFC 4226 §5.4. The low nibble of the last byte picks
    // where to read from, so the whole digest contributes to the output.
    const offset = digest[digest.length - 1]! & 0x0f;

    const value =
        ((digest[offset]! & 0x7f) << 24) |
        ((digest[offset + 1]! & 0xff) << 16) |
        ((digest[offset + 2]! & 0xff) << 8) |
        (digest[offset + 3]! & 0xff);

    return String(value % 10 ** config.digits).padStart(config.digits, '0');
}

/** The code for a moment in time. */
export function totp(config: TotpConfig, secondsSinceEpoch: number): string {
    return hotp(config, counterAt(secondsSinceEpoch, config.period));
}

/** How many seconds the current code has left. Drives the countdown ring. */
export function secondsRemaining(secondsSinceEpoch: number, period: number = DEFAULT_PERIOD): number {
    const elapsed = secondsSinceEpoch - counterAt(secondsSinceEpoch, period) * period;

    return period - Math.floor(elapsed);
}

/**
 * Reads an `otpauth://totp/...` URI, as scanned from a QR code or copied out of
 * a setup page.
 *
 * Deliberately strict about the scheme and the type. `otpauth://hotp/` is a
 * counter-based credential that this application cannot store correctly — it
 * would need to persist and advance a counter on every use — and accepting one
 * would produce codes that are wrong every time after the first.
 */
export function parseOtpauth(uri: string): TotpConfig {
    let parsed: URL;

    try {
        parsed = new URL(uri.trim());
    } catch {
        throw new InvalidParameterError('That is not a valid otpauth:// URI.');
    }

    if (parsed.protocol !== 'otpauth:') {
        throw new InvalidParameterError(`Expected an otpauth:// URI, received “${parsed.protocol}//”.`);
    }

    if (parsed.host.toLowerCase() !== 'totp') {
        throw new InvalidParameterError(
            'Only time-based (totp) URIs are supported. A counter-based hotp credential needs a ' +
                'counter this application does not keep, and would produce a valid code only once.',
        );
    }

    const secret = parsed.searchParams.get('secret');

    if (secret === null || secret === '') {
        throw new InvalidParameterError('That otpauth:// URI carries no secret.');
    }

    // Validates the alphabet now rather than at the first code, so a mistyped
    // seed is refused while the user is still looking at the field.
    decodeBase32(secret);

    /*
     | Both are display-only, and both are genuinely optional in the scheme, so
     | an absent one is omitted rather than stored as an empty string —
     | `exactOptionalPropertyTypes` makes that distinction real, and a blank
     | issuer rendered in the interface reads as a bug.
     */
    const label = decodeURIComponent(parsed.pathname.replace(/^\//, ''));
    const issuer = parsed.searchParams.get('issuer');

    return {
        secret: secret.replace(/[\s-]/g, '').toUpperCase(),
        algorithm: readAlgorithm(parsed.searchParams.get('algorithm')),
        digits: readNumber(parsed.searchParams.get('digits'), DEFAULT_DIGITS, 6, 10, 'digits'),
        period: readNumber(parsed.searchParams.get('period'), DEFAULT_PERIOD, 1, 300, 'period'),
        ...(label === '' ? {} : { label }),
        ...(issuer === null ? {} : { issuer }),
    };
}

/** The URI form, for handing a seed on to a phone. */
export function toOtpauth(config: TotpConfig, account: string, issuer: string): string {
    const parameters = new URLSearchParams({
        secret: config.secret,
        issuer,
        algorithm: config.algorithm,
        digits: String(config.digits),
        period: String(config.period),
    });

    return `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(account)}?${parameters}`;
}

function readAlgorithm(value: string | null): TotpAlgorithm {
    if (value === null || value === '') {
        return DEFAULT_TOTP.algorithm;
    }

    const normalised = value.toUpperCase().replace('-', '');

    if (!TOTP_ALGORITHMS.includes(normalised as TotpAlgorithm)) {
        throw new InvalidParameterError(
            `Unsupported TOTP algorithm “${value}”. Expected one of ${TOTP_ALGORITHMS.join(', ')}.`,
        );
    }

    return normalised as TotpAlgorithm;
}

function readNumber(
    value: string | null,
    fallback: number,
    minimum: number,
    maximum: number,
    field: string,
): number {
    if (value === null || value === '') {
        return fallback;
    }

    const parsed = Number(value);

    if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
        throw new InvalidParameterError(
            `A TOTP ${field} of “${value}” is outside the range ${minimum}–${maximum}.`,
        );
    }

    return parsed;
}

function assertConfig(config: TotpConfig): void {
    if (!TOTP_ALGORITHMS.includes(config.algorithm)) {
        throw new InvalidParameterError(`Unsupported TOTP algorithm “${config.algorithm}”.`);
    }

    if (!Number.isSafeInteger(config.digits) || config.digits < 6 || config.digits > 10) {
        throw new InvalidParameterError(`A TOTP code must be 6 to 10 digits, not ${config.digits}.`);
    }

    if (!Number.isSafeInteger(config.period) || config.period < 1) {
        throw new InvalidParameterError('A TOTP period must be a positive whole number of seconds.');
    }
}

/** A fresh 160-bit seed, matching the SHA-1 block the algorithm is built on. */
export function generateTotpSecret(randomBytes: (length: number) => Uint8Array): string {
    return encodeBase32(randomBytes(20));
}

/** Present-tense helper so call sites do not repeat the milliseconds division. */
export function nowInSeconds(): number {
    return Date.now() / 1000;
}
