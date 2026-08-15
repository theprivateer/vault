/**
 * Comparing two versions of a plaintext, in the browser.
 *
 * This has to be here rather than on the server, and not for a performance
 * reason: **the server cannot diff two ciphertexts.** They are sealed under
 * different Item Keys and it holds neither, so the only place the comparison
 * can happen is the one place both plaintexts exist at once. That is D5 doing
 * what it always does — a feature that would be a database query in an ordinary
 * application becomes a function here.
 *
 * Everything below deals in strings that have already been decrypted. It has no
 * idea what a secret is and holds nothing after it returns.
 */

/** One run of the comparison. `same` runs carry the text once, not twice. */
export interface DiffOp {
    kind: 'same' | 'added' | 'removed';
    text: string;
}

/**
 * The point past which the quadratic table is abandoned.
 *
 * The LCS below allocates `a.length × b.length` cells, so two long notes could
 * ask for a table of tens of millions of entries and lock the tab up in a
 * synchronous loop. Past this bound the answer degrades to "all of this was
 * replaced by all of that", which is true, useful and instant — a diff that
 * hangs the interface is worse than a coarse one.
 *
 * 250,000 cells is a 500-line note against another 500-line note, well beyond
 * anything a credential store holds.
 */
export const MAX_DIFF_CELLS = 250_000;

/**
 * Line-by-line difference between two texts.
 *
 * Line granularity for both a multi-line note and a one-line password: a
 * changed password comes back as one removal and one addition, which is exactly
 * what a reader needs, and a character-level diff of two random strings is
 * noise dressed up as detail.
 */
export function diffLines(before: string, after: string): DiffOp[] {
    const a = before.split('\n');
    const b = after.split('\n');

    if (before === after) {
        return before === '' ? [] : [{ kind: 'same', text: before }];
    }

    if (a.length * b.length > MAX_DIFF_CELLS) {
        return wholesale(a, b);
    }

    return collapse(backtrack(a, b, lengths(a, b)));
}

/** Whether two texts differ at all — cheaper than asking for the difference. */
export function hasChanged(before: string, after: string): boolean {
    return before !== after;
}

/**
 * The classic longest-common-subsequence table, one row per line of `a`.
 *
 * `Int32Array` rather than nested arrays: this is the only allocation in the
 * module that scales with the input, and a flat typed array keeps a
 * five-hundred-line comparison in two megabytes instead of a forest of boxed
 * numbers.
 */
function lengths(a: string[], b: string[]): Int32Array {
    const width = b.length + 1;
    const table = new Int32Array((a.length + 1) * width);

    /*
     | Non-null throughout: every index is bounded by the loop that produced it,
     | and the table was allocated at exactly (a.length + 1) × width. Coalescing
     | to a default instead would add a branch on each read that no input can
     | ever take, which is worse than an assertion — it hides that the bound is
     | already proven.
     */
    for (let i = a.length - 1; i >= 0; i--) {
        for (let j = b.length - 1; j >= 0; j--) {
            table[i * width + j] =
                a[i] === b[j]
                    ? table[(i + 1) * width + j + 1]! + 1
                    : Math.max(table[(i + 1) * width + j]!, table[i * width + j + 1]!);
        }
    }

    return table;
}

/**
 * Walks the table forwards, emitting one op per line.
 *
 * Forwards rather than from the end, so that when a line could be attributed to
 * either side the earlier one wins — which is what makes an insertion read as an
 * insertion rather than as everything after it having moved.
 */
function backtrack(a: string[], b: string[], table: Int32Array): DiffOp[] {
    const width = b.length + 1;
    const ops: DiffOp[] = [];
    let i = 0;
    let j = 0;

    // Non-null as above: both indices are bounded by their own loop conditions.
    while (i < a.length && j < b.length) {
        if (a[i] === b[j]) {
            ops.push({ kind: 'same', text: a[i]! });
            i++;
            j++;
        } else if (table[(i + 1) * width + j]! >= table[i * width + j + 1]!) {
            ops.push({ kind: 'removed', text: a[i]! });
            i++;
        } else {
            ops.push({ kind: 'added', text: b[j]! });
            j++;
        }
    }

    while (i < a.length) {
        ops.push({ kind: 'removed', text: a[i]! });
        i++;
    }

    while (j < b.length) {
        ops.push({ kind: 'added', text: b[j]! });
        j++;
    }

    return ops;
}

/**
 * Everything replaced by everything, for inputs too large to compare line by line.
 *
 * No emptiness guards: `split` always yields at least one element, and this is
 * only reached when the product of the two lengths exceeds the bound, so both
 * sides are non-empty by construction. A guard here would be a branch nothing
 * can take.
 */
function wholesale(a: string[], b: string[]): DiffOp[] {
    return [
        { kind: 'removed', text: a.join('\n') },
        { kind: 'added', text: b.join('\n') },
    ];
}

/**
 * Joins neighbouring ops of the same kind into one run.
 *
 * Rendering is per op, so without this a twenty-line unchanged block becomes
 * twenty elements and the eye has nothing to skip over.
 */
function collapse(ops: DiffOp[]): DiffOp[] {
    const merged: DiffOp[] = [];

    for (const op of ops) {
        const last = merged[merged.length - 1];

        if (last && last.kind === op.kind) {
            last.text = `${last.text}\n${op.text}`;
        } else {
            merged.push({ ...op });
        }
    }

    return merged;
}
