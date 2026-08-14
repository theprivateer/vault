/**
 * Crockford base32, used for recovery codes and key fingerprints.
 *
 * Chosen over base64 and hex because both of those are read aloud, typed from
 * paper, and compared by eye by people under stress. Crockford's alphabet omits
 * I, L, O and U, and decoding folds the characters they get confused with.
 */
import { InvalidParameterError } from './errors';

const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

/*
 | Ambiguous characters fold to what the user meant: I and L to 1, O to 0.
 |
 | U is deliberately not folded. It is excluded from the alphabet to avoid
 | accidental obscenity, and Crockford treats it as invalid input — silently
 | rewriting a U to something else would corrupt a recovery code and present as
 | an unexplained failure to unlock.
 */

export function encodeBase32(bytes: Uint8Array): string {
    let output = '';
    let buffer = 0;
    let bits = 0;

    for (const byte of bytes) {
        buffer = (buffer << 8) | byte;
        bits += 8;

        while (bits >= 5) {
            bits -= 5;
            output += ALPHABET[(buffer >> bits) & 0b11111];
        }
    }

    if (bits > 0) {
        output += ALPHABET[(buffer << (5 - bits)) & 0b11111];
    }

    return output;
}

/**
 * Decodes Crockford base32, tolerating the ways a human transcribes it:
 * lowercase, grouping separators, and the ambiguous letter substitutions.
 */
export function decodeBase32(input: string): Uint8Array {
    const normalised = input.toUpperCase().replace(/[\s-]/g, '').replace(/[IL]/g, '1').replace(/O/g, '0');

    const bytes: number[] = [];
    let buffer = 0;
    let bits = 0;

    for (const character of normalised) {
        const value = ALPHABET.indexOf(character);

        if (value === -1) {
            throw new InvalidParameterError(`Invalid character in recovery code: ${character}`);
        }

        buffer = (buffer << 5) | value;
        bits += 5;

        if (bits >= 8) {
            bits -= 8;
            bytes.push((buffer >> bits) & 0xff);
        }
    }

    return Uint8Array.from(bytes);
}

/** Splits a string into fixed-size groups, for display on paper. */
export function group(value: string, size = 4, separator = '-'): string {
    return (value.match(new RegExp(`.{1,${size}}`, 'g')) ?? []).join(separator);
}
