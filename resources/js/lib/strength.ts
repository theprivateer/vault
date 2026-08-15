/**
 * Estimating the strength of a password somebody typed.
 *
 * **This is weaker than zxcvbn and the interface says so.** zxcvbn was the
 * specified option and was not taken: it is three packages and several hundred
 * kilobytes of dictionaries against a threat model whose A10 entry names a
 * deliberately small dependency surface as a defence. Dropping that principle
 * for a progress bar would have been a poor trade, so what is here is smaller,
 * auditable in one sitting, and honest about the gap.
 *
 * What it will miss, stated plainly because a strength meter that overstates is
 * worse than none at all: dictionary words, names, l33t-speak substitutions and
 * passwords from breach corpora all score higher here than they deserve.
 * `correcthorse` is not treated as two words. What it does catch is the
 * structure that actually shows up — reuse of a single class, repetition,
 * sequences, keyboard runs, dates, and the handful of passwords that appear at
 * the top of every leak.
 *
 * The distinction that matters, and the one the UI draws: for a value from
 * `generate.ts` the entropy is *arithmetic*, because the process is known. For
 * anything a human typed it is a guess, and this module returns a guess.
 */

/** Where a password lands. Five buckets, because more would imply precision. */
export const STRENGTH_LABELS = ['very weak', 'weak', 'fair', 'strong', 'very strong'] as const;

export type StrengthLabel = (typeof STRENGTH_LABELS)[number];

export interface Strength {
    /** Estimated bits, after penalties. Never above the raw character-space figure. */
    bits: number;
    /** 0–4, indexing STRENGTH_LABELS. */
    score: number;
    label: StrengthLabel;
    /** What dragged the estimate down, in the user's words. Possibly empty. */
    warnings: string[];
}

/**
 * Bit thresholds for each score.
 *
 * Chosen against offline attack on a *well-stored* credential, which is the
 * situation this application is actually in: an Argon2id-wrapped User Key at 64
 * MiB and 3 passes is somewhere around 10⁴–10⁵ guesses per second on good
 * hardware, so 60 bits is genuinely uncomfortable and 80 is not. A password
 * typed into a website that stores it as unsalted SHA-1 needs far more, and no
 * meter can know which it is.
 */
const THRESHOLDS = [28, 40, 60, 80];

/**
 * The passwords that appear at the top of every breach corpus.
 *
 * A deliberately tiny list — a real one is megabytes, which is the dependency
 * that was declined. It exists so the most common inputs cannot score "fair",
 * not as a substitute for a dictionary.
 */
const COMMON = new Set([
    'password',
    'passw0rd',
    'p@ssword',
    'p@ssw0rd',
    '123456',
    '12345678',
    '123456789',
    '1234567890',
    'qwerty',
    'qwertyuiop',
    'abc123',
    'letmein',
    'monkey',
    'dragon',
    'baseball',
    'football',
    'iloveyou',
    'admin',
    'welcome',
    'login',
    'princess',
    'sunshine',
    'master',
    'shadow',
    'trustno1',
    'superman',
    'starwars',
    'whatever',
    'changeme',
    'secret',
    'default',
    'root',
]);

/** Rows as fingers meet them, for detecting runs like `asdf` or `1qaz`. */
const KEYBOARD_ROWS = ['`1234567890-=', 'qwertyuiop[]\\', "asdfghjkl;'", 'zxcvbnm,./'];

const CLASS_SIZES: ReadonlyArray<{ pattern: RegExp; size: number }> = [
    { pattern: /[a-z]/, size: 26 },
    { pattern: /[A-Z]/, size: 26 },
    { pattern: /[0-9]/, size: 10 },
    { pattern: /[^a-zA-Z0-9]/, size: 33 },
];

/**
 * Estimates the strength of a typed password.
 *
 * The shape of the calculation: start from the character-space entropy, then
 * subtract for structure that shrinks the space an attacker actually has to
 * search. Penalties are in bits and are deliberately blunt — the aim is to move
 * a password across a threshold it should not have been above, not to model a
 * cracking run.
 */
export function estimateStrength(password: string): Strength {
    if (password === '') {
        return { bits: 0, score: 0, label: 'very weak', warnings: [] };
    }

    const warnings: string[] = [];
    let bits = rawBits(password);

    const normalised = password.toLowerCase();

    if (COMMON.has(normalised)) {
        /*
         | Not a penalty but a ceiling. A password on a public list is found in
         | the first few thousand guesses whatever its length, so scaling its
         | character-space entropy down by some factor would still leave a
         | fourteen-character one looking respectable.
         */
        return {
            bits: Math.min(bits, 8),
            score: 0,
            label: 'very weak',
            warnings: ['This is one of the most common passwords in existence. It is guessed first.'],
        };
    }

    const repeats = repeatPenalty(password);

    if (repeats > 0) {
        bits -= repeats;
        warnings.push('Repeated characters add much less than they look like they do.');
    }

    const runs = sequencePenalty(normalised);

    if (runs > 0) {
        bits -= runs;
        warnings.push('Runs like “abcd” or “4321” are among the first things tried.');
    }

    const keyboard = keyboardPenalty(normalised);

    if (keyboard > 0) {
        bits -= keyboard;
        warnings.push('Keyboard patterns are in every cracking wordlist.');
    }

    if (looksLikeYear(password)) {
        bits -= 6;
        warnings.push('A year narrows the search to about a hundred possibilities.');
    }

    const classes = CLASS_SIZES.filter(({ pattern }) => pattern.test(password)).length;

    if (classes === 1 && password.length < 16) {
        warnings.push('One kind of character only. Length or variety — either helps.');
    }

    /*
     | The honest limit, surfaced rather than hidden. A long run of lower-case
     | letters scores well here and might be a dictionary word, which this
     | module cannot tell. Better to say so than to report a number that is
     | confidently wrong.
     */
    if (classes === 1 && /^[a-z]+$/.test(password) && password.length >= 8) {
        warnings.push(
            'If this is a word or a name, it is far weaker than the score suggests — this check ' +
                'does not carry a dictionary.',
        );
    }

    bits = Math.max(0, bits);

    return { bits, score: scoreFor(bits), label: STRENGTH_LABELS[scoreFor(bits)] ?? 'very weak', warnings };
}

/** log2(alphabet) × length, the optimistic starting point. */
export function rawBits(password: string): number {
    const alphabet = CLASS_SIZES.reduce(
        (total, { pattern, size }) => total + (pattern.test(password) ? size : 0),
        0,
    );

    return alphabet === 0 ? 0 : Math.log2(alphabet) * password.length;
}

function scoreFor(bits: number): number {
    return THRESHOLDS.filter((threshold) => bits >= threshold).length;
}

/**
 * Charges for characters that repeat the one before them.
 *
 * `aaaaaaaa` has the character-space entropy of eight letters and the real
 * entropy of one, so each repeat gives back almost everything it claimed.
 */
function repeatPenalty(password: string): number {
    let repeated = 0;

    for (let index = 1; index < password.length; index++) {
        if (password[index] === password[index - 1]) {
            repeated++;
        }
    }

    return repeated * Math.log2(26) * 0.9;
}

/** Charges for ascending or descending runs of three or more. */
function sequencePenalty(password: string): number {
    let penalty = 0;
    let run = 1;

    for (let index = 1; index < password.length; index++) {
        const step = password.charCodeAt(index) - password.charCodeAt(index - 1);

        if (step === 1 || step === -1) {
            run++;
        } else {
            penalty += chargeForRun(run);
            run = 1;
        }
    }

    return penalty + chargeForRun(run);
}

function chargeForRun(run: number): number {
    // A run of n is roughly one choice plus a direction, not n choices.
    return run >= 3 ? (run - 1) * Math.log2(26) * 0.8 : 0;
}

/** Charges for adjacent keys on the same row, in either direction. */
function keyboardPenalty(password: string): number {
    let penalty = 0;
    let run = 1;

    for (let index = 1; index < password.length; index++) {
        if (adjacentOnKeyboard(password[index - 1] ?? '', password[index] ?? '')) {
            run++;
        } else {
            penalty += chargeForRun(run);
            run = 1;
        }
    }

    return penalty + chargeForRun(run);
}

function adjacentOnKeyboard(a: string, b: string): boolean {
    return KEYBOARD_ROWS.some((row) => {
        const first = row.indexOf(a);
        const second = row.indexOf(b);

        return first !== -1 && second !== -1 && Math.abs(first - second) === 1;
    });
}

/** A four-digit run that reads as a plausible year. */
function looksLikeYear(password: string): boolean {
    return /(19|20)\d{2}/.test(password);
}
