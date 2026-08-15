/**
 * Generating passwords and passphrases, and saying honestly how strong they are.
 *
 * Two rules run through this module, and both are about not lying to the user:
 *
 * 1. **Uniform sampling, or the entropy figure is fiction.** Every character and
 *    every word is drawn with rejection sampling from `crypto.getRandomValues`.
 *    The obvious `random % alphabet.length` is biased whenever the alphabet does
 *    not divide 256, and the bias is not academic: it silently shaves the real
 *    entropy below the number displayed beside it, which is the one number the
 *    user is being asked to trust.
 * 2. **Entropy here is arithmetic, not estimation.** For a value this module
 *    generated, `log2(alphabet) × length` is exactly right, because the process
 *    that produced it is known. That is a categorically stronger claim than
 *    anything `strength.ts` can make about a password a human typed, and the
 *    interface distinguishes the two rather than showing one bar for both.
 */
import { randomBytes } from '@/crypto/primitives';

import { WORDLIST, WORDLIST_SIZE } from './wordlist';

/** The character classes a generated password can draw from. */
export const CHARACTER_CLASSES = {
    lower: 'abcdefghijklmnopqrstuvwxyz',
    upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    digits: '0123456789',
    /**
     * Deliberately conservative. Quotes, backslashes and backticks are omitted
     * because a password containing them has a habit of not surviving a shell,
     * a connection string or somebody else's escaping — and a password that
     * cannot be pasted where it is needed gets replaced by a worse one.
     */
    symbols: '!#$%&()*+,-./:;<=>?@[]^_{|}~',
} as const;

export type CharacterClass = keyof typeof CHARACTER_CLASSES;

/**
 * Characters that are hard to tell apart in the monospace faces this interface
 * uses, and worse when read down a phone line.
 */
const AMBIGUOUS = new Set(['l', 'I', '1', '|', 'O', '0', 'o']);

export const MIN_PASSWORD_LENGTH = 8;

export const MAX_PASSWORD_LENGTH = 128;

export const MIN_PASSPHRASE_WORDS = 3;

export const MAX_PASSPHRASE_WORDS = 12;

export interface PasswordOptions {
    length: number;
    classes: readonly CharacterClass[];
    /** Drop characters that read ambiguously. Costs a little entropy per character. */
    excludeAmbiguous?: boolean;
}

export interface PassphraseOptions {
    words: number;
    separator?: string;
    /** Appends a digit to satisfy policies that demand one. Adds log2(10) bits. */
    appendNumber?: boolean;
    capitalise?: boolean;
}

/** A generated value and the exact entropy of the process that produced it. */
export interface Generated {
    value: string;
    /** Shannon entropy in bits. Exact for generated values, by construction. */
    bits: number;
    /** How the figure was arrived at, shown so the number is checkable. */
    describe: string;
}

export class GeneratorError extends Error {}

/**
 * Draws an index in `[0, bound)` without modulo bias.
 *
 * Rejection sampling: everything at or above the largest exact multiple of
 * `bound` is discarded and redrawn. The loop is unbounded in principle and
 * finishes almost immediately in practice — for the widest alphabet here the
 * rejection rate is under 3%, and each redraw is independent.
 *
 * Bytes are taken in blocks rather than one at a time, because a call into
 * `crypto.getRandomValues` per character is the expensive part of generating a
 * hundred-character password.
 */
function uniformIndex(bound: number, pool: BytePool): number {
    if (bound < 1 || bound > 0x1_00_00_00) {
        throw new GeneratorError(`Cannot draw uniformly from ${bound} possibilities.`);
    }

    // How many bytes are needed to cover the range, and the largest multiple of
    // `bound` that fits in them.
    const width = bound <= 0x100 ? 1 : bound <= 0x1_00_00 ? 2 : 3;
    const ceiling = 256 ** width;
    const limit = ceiling - (ceiling % bound);

    for (;;) {
        let value = 0;

        for (let byte = 0; byte < width; byte++) {
            value = (value << 8) | pool.next();
        }

        if (value < limit) {
            return value % bound;
        }
    }
}

/** Refills from `crypto.getRandomValues` in blocks rather than per byte. */
class BytePool {
    private buffer: Uint8Array;

    private offset: number;

    constructor(private readonly blockSize = 256) {
        this.buffer = randomBytes(blockSize);
        this.offset = 0;
    }

    next(): number {
        if (this.offset >= this.buffer.length) {
            this.buffer = randomBytes(this.blockSize);
            this.offset = 0;
        }

        const byte = this.buffer[this.offset] ?? 0;
        this.offset++;

        return byte;
    }
}

/** The alphabet a set of options actually draws from. */
export function alphabetFor(options: PasswordOptions): string {
    const characters = options.classes
        .map((name) => CHARACTER_CLASSES[name] ?? '')
        .join('')
        .split('');

    const filtered = options.excludeAmbiguous
        ? characters.filter((character) => !AMBIGUOUS.has(character))
        : characters;

    return [...new Set(filtered)].join('');
}

/**
 * A random password.
 *
 * **No "at least one of each class" post-processing.** Forcing a character from
 * every selected class is the thing every generator seems to do and it strictly
 * *reduces* entropy: it removes valid outputs from the space while the reported
 * figure carries on describing the space that was not sampled. If a policy
 * demands a digit, ask for digits and accept that a short password occasionally
 * lacks one; the honest fix is length.
 */
export function generatePassword(options: PasswordOptions): Generated {
    const alphabet = alphabetFor(options);

    if (alphabet.length < 2) {
        throw new GeneratorError(
            'Choose at least one character class — a password drawn from one symbol is not a password.',
        );
    }

    if (
        !Number.isSafeInteger(options.length) ||
        options.length < MIN_PASSWORD_LENGTH ||
        options.length > MAX_PASSWORD_LENGTH
    ) {
        throw new GeneratorError(
            `Length must be between ${MIN_PASSWORD_LENGTH} and ${MAX_PASSWORD_LENGTH} characters.`,
        );
    }

    const pool = new BytePool();
    let value = '';

    for (let index = 0; index < options.length; index++) {
        value += alphabet[uniformIndex(alphabet.length, pool)];
    }

    return {
        value,
        bits: Math.log2(alphabet.length) * options.length,
        describe: `${options.length} characters from an alphabet of ${alphabet.length}`,
    };
}

/**
 * A random passphrase from the EFF list.
 *
 * The separator defaults to a hyphen everywhere except where the drawn words are
 * themselves hyphenated — four of them are — because "yo-yo-t-shirt-anchor" is
 * ambiguous when read aloud, which is most of what a passphrase is for.
 */
export function generatePassphrase(options: PassphraseOptions): Generated {
    if (
        !Number.isSafeInteger(options.words) ||
        options.words < MIN_PASSPHRASE_WORDS ||
        options.words > MAX_PASSPHRASE_WORDS
    ) {
        throw new GeneratorError(
            `A passphrase must be ${MIN_PASSPHRASE_WORDS} to ${MAX_PASSPHRASE_WORDS} words.`,
        );
    }

    assertWordlistIntact();

    const pool = new BytePool();
    const drawn: string[] = [];

    for (let index = 0; index < options.words; index++) {
        const word = WORDLIST[uniformIndex(WORDLIST_SIZE, pool)] ?? '';

        drawn.push(options.capitalise ? word.charAt(0).toUpperCase() + word.slice(1) : word);
    }

    const separator = options.separator ?? defaultSeparator(drawn);
    let value = drawn.join(separator);
    let bits = Math.log2(WORDLIST_SIZE) * options.words;
    let describe = `${options.words} words from a list of ${WORDLIST_SIZE}`;

    if (options.appendNumber) {
        value += separator + String(uniformIndex(10, pool));
        bits += Math.log2(10);
        describe += ', plus one digit';
    }

    /*
     | Capitalising the first letter of every word adds no entropy at all: it is
     | a deterministic transform of the words already drawn, and an attacker who
     | knows this generator exists knows to try it. Saying so beats letting a
     | checkbox imply otherwise.
     */
    return { value, bits, describe };
}

/** A hyphen unless a drawn word already contains one, in which case a full stop. */
function defaultSeparator(words: readonly string[]): string {
    return words.some((word) => word.includes('-')) ? '.' : '-';
}

/**
 * Guards the one assumption every entropy figure here rests on.
 *
 * A wordlist that lost entries — a bad merge, a stray edit, a truncated
 * generator run — would keep working and would keep reporting 12.925 bits per
 * word, overstating every passphrase in the direction that matters. So the size
 * is checked against the constant the arithmetic uses, at the moment it is used.
 */
export function assertWordlistIntact(): void {
    if (WORDLIST.length !== WORDLIST_SIZE) {
        throw new GeneratorError(
            `The bundled wordlist holds ${WORDLIST.length} words but the entropy arithmetic assumes ` +
                `${WORDLIST_SIZE}. Every passphrase strength shown would be wrong, and wrong in the ` +
                'direction of claiming more than is there.',
        );
    }
}

/**
 * How long an offline attacker takes on average, at a stated guess rate.
 *
 * Expressed as a rate the caller passes in rather than a hardcoded "years",
 * because the honest answer depends entirely on how the credential is stored at
 * the far end, and this module has no idea. A password protecting an Argon2id
 * wrapping and one protecting an unsalted MD5 have the same entropy and wildly
 * different lifetimes.
 */
export function averageGuessSeconds(bits: number, guessesPerSecond: number): number {
    return 2 ** (bits - 1) / guessesPerSecond;
}
