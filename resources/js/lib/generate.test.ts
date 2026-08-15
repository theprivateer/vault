/**
 * Generators, and the one property that makes their entropy figure honest.
 *
 * The claim on screen is "this many bits, exactly". That is only true if every
 * character and every word is drawn uniformly, so the distribution tests below
 * are not statistical decoration — they are the thing being asserted. A
 * `random % alphabet.length` implementation passes every other test in this file
 * and fails those.
 */
import { describe, expect, it } from 'vitest';

import {
    alphabetFor,
    assertWordlistIntact,
    averageGuessSeconds,
    CHARACTER_CLASSES,
    generatePassphrase,
    generatePassword,
    GeneratorError,
    MAX_PASSWORD_LENGTH,
} from './generate';
import { WORDLIST, WORDLIST_SIZE } from './wordlist';

describe('the bundled wordlist', () => {
    /*
     | Every passphrase entropy figure is log2 of this number. A list that lost
     | entries would keep working and would keep claiming 12.9 bits per word,
     | overstating in the direction that matters.
     */
    it('is exactly the EFF large list', () => {
        expect(WORDLIST).toHaveLength(WORDLIST_SIZE);
        expect(WORDLIST_SIZE).toBe(6 ** 5);
        expect(new Set(WORDLIST).size).toBe(WORDLIST_SIZE);
        expect(assertWordlistIntact()).toBeUndefined();
    });

    it('holds only characters that survive being typed and spoken', () => {
        expect(WORDLIST.every((word) => /^[a-z-]+$/.test(word))).toBe(true);
    });
});

describe('generating a password', () => {
    it('produces the requested length from the requested classes', () => {
        const { value, bits } = generatePassword({ length: 24, classes: ['lower', 'digits'] });

        expect(value).toHaveLength(24);
        expect(value).toMatch(/^[a-z0-9]{24}$/);
        expect(bits).toBeCloseTo(Math.log2(36) * 24, 6);
    });

    it('reports entropy as arithmetic over the alphabet it actually used', () => {
        const all = generatePassword({
            length: 20,
            classes: ['lower', 'upper', 'digits', 'symbols'],
        });

        const alphabet = alphabetFor({ length: 20, classes: ['lower', 'upper', 'digits', 'symbols'] });

        expect(all.bits).toBeCloseTo(Math.log2(alphabet.length) * 20, 6);
        expect(all.describe).toContain(String(alphabet.length));
    });

    it('shrinks the alphabet, and the claim, when ambiguous characters are excluded', () => {
        const options = { length: 20, classes: ['lower', 'digits'] as const };

        const plain = alphabetFor({ ...options, excludeAmbiguous: false });
        const filtered = alphabetFor({ ...options, excludeAmbiguous: true });

        expect(filtered.length).toBeLessThan(plain.length);
        expect(filtered).not.toContain('l');
        expect(filtered).not.toContain('0');

        // The reported bits follow the smaller alphabet rather than the asked-for
        // one, which is the whole point of computing them from `alphabetFor`.
        expect(generatePassword({ ...options, excludeAmbiguous: true }).bits).toBeCloseTo(
            Math.log2(filtered.length) * 20,
            6,
        );
    });

    it('refuses settings it cannot honour', () => {
        expect(() => generatePassword({ length: 20, classes: [] })).toThrow(GeneratorError);
        expect(() => generatePassword({ length: 4, classes: ['lower'] })).toThrow(GeneratorError);
        expect(() => generatePassword({ length: MAX_PASSWORD_LENGTH + 1, classes: ['lower'] })).toThrow(
            GeneratorError,
        );
    });

    /**
     * The distribution test, as a chi-squared statistic rather than per-character
     * bounds.
     *
     * Bounds on each of 62 counts are the obvious approach and are badly flaky:
     * at any width tight enough to catch a bias, a correct generator trips one
     * of the 62 by chance often enough to be useless. One aggregate over the
     * whole distribution has the sensitivity without the false alarms.
     *
     * With 61 degrees of freedom a uniform generator gives χ² ≈ 61 and exceeds
     * 150 about once in ten million runs. The bug this exists to catch —
     * `random % 62`, which favours the first eight characters by 25% because
     * 256 is not a multiple of 62 — produces χ² above 800 at this sample size.
     * So the threshold sits in a very wide gap, which is what makes it a test
     * rather than a coin flip.
     */
    it('draws characters uniformly, so the entropy figure is not fiction', () => {
        const classes = ['lower', 'upper', 'digits'] as const;
        const alphabet = alphabetFor({ length: 8, classes });
        const counts = new Map<string, number>();
        const draws = alphabet.length * 2_000;

        for (let batch = 0; batch < draws / 100; batch++) {
            for (const character of generatePassword({ length: 100, classes }).value) {
                counts.set(character, (counts.get(character) ?? 0) + 1);
            }
        }

        expect(counts.size).toBe(alphabet.length);

        const expected = draws / alphabet.length;
        const chiSquared = [...counts.values()].reduce(
            (total, count) => total + (count - expected) ** 2 / expected,
            0,
        );

        expect(chiSquared, `chi-squared was ${chiSquared.toFixed(1)} over ${draws} draws`).toBeLessThan(150);
    });

    it('does not repeat itself', () => {
        const values = new Set(
            Array.from({ length: 50 }, () => generatePassword({ length: 16, classes: ['lower'] }).value),
        );

        expect(values.size).toBe(50);
    });
});

describe('generating a passphrase', () => {
    it('draws the requested number of words from the list', () => {
        const { value, bits } = generatePassphrase({ words: 5 });
        const words = value.split(/[-.]/);

        expect(words).toHaveLength(5);
        expect(words.every((word) => WORDLIST.includes(word))).toBe(true);
        expect(bits).toBeCloseTo(Math.log2(WORDLIST_SIZE) * 5, 6);
    });

    it('adds exactly log2(10) bits for an appended digit', () => {
        const plain = generatePassphrase({ words: 4 });
        const numbered = generatePassphrase({ words: 4, appendNumber: true });

        expect(numbered.bits - plain.bits).toBeCloseTo(Math.log2(10), 6);
        expect(numbered.value).toMatch(/[-.]\d$/);
    });

    /*
     | Capitalising is a deterministic transform of words already drawn, so it
     | adds nothing an attacker who knows this generator exists has to search.
     | The figure must not move.
     */
    it('claims no extra entropy for capitalisation', () => {
        expect(generatePassphrase({ words: 5, capitalise: true }).bits).toBeCloseTo(
            generatePassphrase({ words: 5 }).bits,
            6,
        );

        expect(generatePassphrase({ words: 5, capitalise: true }).value).toMatch(/^[A-Z]/);
    });

    /*
     | Four EFF words are hyphenated. Joining those with a hyphen produces
     | something ambiguous to read aloud, which is most of what a passphrase is
     | for, so the separator moves out of the way instead.
     */
    it('avoids a hyphen separator when a drawn word already has one', () => {
        const withHyphen = ['t-shirt', 'yo-yo', 'drop-down', 'felt-tip'];

        // Sampled until a hyphenated word turns up, rather than stubbing the
        // generator: the behaviour under test is the real draw path.
        let sawHyphenated = false;

        for (let attempt = 0; attempt < 3_000 && !sawHyphenated; attempt++) {
            const { value } = generatePassphrase({ words: 8 });

            if (withHyphen.some((word) => value.includes(word))) {
                sawHyphenated = true;
                expect(value).toContain('.');
            }
        }

        expect(sawHyphenated, 'no hyphenated word was drawn in 24,000 samples').toBe(true);
    });

    it('honours an explicit separator', () => {
        expect(generatePassphrase({ words: 3, separator: ' ' }).value.split(' ')).toHaveLength(3);
    });

    it('refuses a length outside the bounds', () => {
        expect(() => generatePassphrase({ words: 1 })).toThrow(GeneratorError);
        expect(() => generatePassphrase({ words: 100 })).toThrow(GeneratorError);
    });

    /** The same uniformity property, over 7,776 possibilities. */
    it('draws words uniformly', () => {
        const counts = new Map<string, number>();
        const draws = 40_000;

        for (let batch = 0; batch < draws / 10; batch++) {
            for (const word of generatePassphrase({ words: 10, separator: ' ' }).value.split(' ')) {
                counts.set(word, (counts.get(word) ?? 0) + 1);
            }
        }

        /*
         | With 40,000 draws over 7,776 words the expected count is about 5, far
         | too few to bound individually. What a modulo bias would show up as is
         | a *coverage* skew — the low indices over-represented — so the check is
         | that the first and last thirds of the list are drawn about equally
         | often, which is exactly where the bias would land.
         */
        const third = Math.floor(WORDLIST_SIZE / 3);
        const tally = (from: number, to: number) =>
            WORDLIST.slice(from, to).reduce((sum, word) => sum + (counts.get(word) ?? 0), 0);

        const first = tally(0, third);
        const last = tally(WORDLIST_SIZE - third, WORDLIST_SIZE);

        expect(first / last).toBeGreaterThan(0.9);
        expect(first / last).toBeLessThan(1.1);
    });
});

describe('describing the cost of guessing', () => {
    /*
     | Expressed against a caller-supplied rate rather than baked in, because the
     | honest answer depends on how the far end stores the credential — and this
     | module has no idea which far end it is.
     */
    it('halves the search space, and scales with the attacker’s rate', () => {
        expect(averageGuessSeconds(40, 1)).toBeCloseTo(2 ** 39, 0);
        expect(averageGuessSeconds(40, 1_000)).toBeCloseTo(2 ** 39 / 1_000, 0);
    });
});

describe('the alphabet', () => {
    it('is the union of the chosen classes, without duplicates', () => {
        const alphabet = alphabetFor({ length: 8, classes: ['lower', 'lower', 'digits'] });

        expect(alphabet).toHaveLength(CHARACTER_CLASSES.lower.length + CHARACTER_CLASSES.digits.length);
        expect(new Set(alphabet).size).toBe(alphabet.length);
    });
});
