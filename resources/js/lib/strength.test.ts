/**
 * The strength estimator, and an honest account of where it stops.
 *
 * These tests assert two kinds of thing. The first is that structure is
 * penalised: repeats, runs, keyboard patterns and dates all shrink the estimate
 * below the character-space figure, because they shrink the space an attacker
 * has to search. The second is unusual, and deliberate — there are tests here
 * pinning the *limits*, so that "this scores a dictionary word too highly" is a
 * documented property rather than a bug somebody discovers later and quietly
 * disagrees with.
 */
import { describe, expect, it } from 'vitest';

import { estimateStrength, rawBits, STRENGTH_LABELS } from './strength';

describe('the raw figure', () => {
    it('is log2(alphabet) × length over the classes present', () => {
        expect(rawBits('abcdefgh')).toBeCloseTo(Math.log2(26) * 8, 6);
        expect(rawBits('abcDEF12')).toBeCloseTo(Math.log2(62) * 8, 6);
        expect(rawBits('')).toBe(0);
    });

    it('counts symbols as their own class', () => {
        expect(rawBits('abc!')).toBeGreaterThan(rawBits('abcd'));
    });
});

describe('scoring', () => {
    it('gives an empty password nothing at all', () => {
        expect(estimateStrength('')).toEqual({ bits: 0, score: 0, label: 'very weak', warnings: [] });
    });

    it('rates a long mixed random password highly', () => {
        const strength = estimateStrength('7Kq!vZm2xR#pLw9Tb$e4');

        expect(strength.score).toBe(4);
        expect(strength.label).toBe('very strong');
        expect(strength.bits).toBeGreaterThan(80);
    });

    it('rates a short one very weak', () => {
        expect(estimateStrength('abc').score).toBe(0);
    });

    it('never reports a score outside the labels it has', () => {
        for (const password of ['a', 'abc123', 'Tr0ub4dor&3', 'x'.repeat(200)]) {
            const { score, label } = estimateStrength(password);

            expect(score).toBeGreaterThanOrEqual(0);
            expect(score).toBeLessThan(STRENGTH_LABELS.length);
            expect(label).toBe(STRENGTH_LABELS[score]);
        }
    });
});

describe('the patterns it does catch', () => {
    /*
     | A ceiling rather than a penalty. A password on a public list is found in
     | the first few thousand guesses whatever its length, so scaling its
     | character-space entropy would still leave a long one looking respectable.
     */
    it('caps a password from every breach corpus, regardless of length', () => {
        const strength = estimateStrength('qwertyuiop');

        expect(strength.score).toBe(0);
        expect(strength.bits).toBeLessThanOrEqual(8);
        expect(strength.warnings[0]).toContain('most common passwords');
    });

    it('catches it whatever the case', () => {
        expect(estimateStrength('PassWord').score).toBe(0);
    });

    it('charges for repeated characters', () => {
        const repeated = estimateStrength('aaaaaaaaaaaaaaaa');

        expect(repeated.bits).toBeLessThan(rawBits('aaaaaaaaaaaaaaaa') / 2);
        expect(repeated.warnings.join(' ')).toContain('Repeated characters');
    });

    it('charges for ascending and descending runs', () => {
        expect(estimateStrength('abcdefghijkl').bits).toBeLessThan(rawBits('abcdefghijkl') / 2);
        expect(estimateStrength('987654321').warnings.join(' ')).toContain('Runs like');
    });

    it('charges for keyboard patterns', () => {
        const strength = estimateStrength('asdfghjkl');

        expect(strength.bits).toBeLessThan(rawBits('asdfghjkl'));
        expect(strength.warnings.join(' ')).toMatch(/Keyboard patterns|Runs like/);
    });

    it('charges for a year', () => {
        // Same length and same character classes, so only the year differs —
        // comparing against a letters-only string would be measuring the
        // alphabet rather than the penalty.
        const withYear = estimateStrength('xkQpvZmw1998');
        const without = estimateStrength('xkQpvZmw1358');

        expect(withYear.warnings.join(' ')).toContain('year');
        expect(withYear.bits).toBeLessThan(without.bits);
    });

    it('mentions when only one kind of character is used', () => {
        expect(estimateStrength('qxvzmwpk').warnings.join(' ')).toContain('One kind of character');
    });
});

describe('the limits, asserted so they are not mistaken for bugs', () => {
    /*
     | zxcvbn scores this near zero. Here it does not, because there is no
     | dictionary — the trade recorded in .ai/rules and docs/02. What the module
     | must do is *say so*, so the warning is the assertion.
     */
    it('overrates a dictionary word, and admits it', () => {
        const strength = estimateStrength('correcthorse');

        expect(strength.score).toBeGreaterThan(0);
        expect(strength.warnings.join(' ')).toContain('does not carry a dictionary');
    });

    it('overrates l33t-speak, which it cannot see through', () => {
        // `p@ssw0rd` is on the small common list; a variant one step away is not.
        expect(estimateStrength('p@55w0rd!').score).toBeGreaterThan(0);
    });

    /*
     | The warning appears only once the score starts looking reassuring, which
     | is when the omission begins to matter. A three-letter password does not
     | need a lecture about dictionaries.
     */
    it('stays quiet about the dictionary gap when the score is already bad', () => {
        expect(estimateStrength('abcd').warnings.join(' ')).not.toContain('does not carry a dictionary');
    });
});

describe('never reporting less than nothing', () => {
    it('floors at zero however heavily penalised', () => {
        expect(estimateStrength('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa').bits).toBeGreaterThanOrEqual(0);
        expect(estimateStrength('abcdefghijklmnopqrstuvwxyz').bits).toBeGreaterThanOrEqual(0);
    });
});
