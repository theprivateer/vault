/**
 * The comparison that only the browser can perform.
 *
 * Two versions of a secret are ciphertext under different Item Keys, and the
 * server holds neither, so a diff is arithmetic on plaintext that exists in
 * exactly one place. These tests care about two things: that the result is
 * faithful, and that a pathological input cannot lock the tab up in a
 * quadratic loop.
 */
import { describe, expect, it } from 'vitest';

import { diffLines, hasChanged, MAX_DIFF_CELLS, type DiffOp } from './diff';

/** The rendered shape, which is what a reader actually sees. */
function render(ops: DiffOp[]): string {
    return ops
        .map((op) => `${op.kind === 'added' ? '+' : op.kind === 'removed' ? '-' : ' '}${op.text}`)
        .join('|');
}

describe('comparing two texts', () => {
    it('reports nothing for identical input', () => {
        expect(diffLines('same', 'same')).toEqual([{ kind: 'same', text: 'same' }]);
        expect(diffLines('', '')).toEqual([]);
    });

    /*
     | The single most common case in this application: a password replaced by
     | another. One removal and one addition is the whole truth — a
     | character-level comparison of two random strings would be noise dressed
     | up as detail.
     */
    it('reports a replaced one-liner as one removal and one addition', () => {
        expect(render(diffLines('hunter2', 'correct-horse'))).toBe('-hunter2|+correct-horse');
    });

    it('keeps the unchanged lines around a change', () => {
        const ops = diffLines('alpha\nbeta\ngamma', 'alpha\ndelta\ngamma');

        expect(render(ops)).toBe(' alpha|-beta|+delta| gamma');
    });

    it('reads an insertion as an insertion rather than as everything moving', () => {
        const ops = diffLines('one\ntwo', 'one\nextra\ntwo');

        expect(render(ops)).toBe(' one|+extra| two');
    });

    it('handles a value appearing where there was none', () => {
        expect(render(diffLines('', 'first note'))).toBe('-|+first note');
        expect(render(diffLines('had notes', ''))).toBe('-had notes|+');
    });

    /*
     | Runs are joined so a twenty-line unchanged block renders as one element.
     | Without it the eye has nothing to skip over, and the diff of a long note
     | becomes a wall of individually styled lines.
     */
    it('joins neighbouring lines of the same kind into one run', () => {
        const ops = diffLines('a\nb\nc\nx', 'a\nb\nc\ny');

        expect(ops).toEqual([
            { kind: 'same', text: 'a\nb\nc' },
            { kind: 'removed', text: 'x' },
            { kind: 'added', text: 'y' },
        ]);
    });

    it('reports a wholly rewritten block without pretending lines survived', () => {
        expect(render(diffLines('a\nb', 'c\nd'))).toBe('-a\nb|+c\nd');
    });

    /*
     | The two tails: everything after a common prefix removed, and everything
     | after one appended. Both fall out of the loops that run once the shorter
     | side is exhausted, which nothing above reaches.
     */
    it('handles a truncated tail and an appended one', () => {
        expect(render(diffLines('a\nb\nc', 'a'))).toBe(' a|-b\nc');
        expect(render(diffLines('a', 'a\nb\nc'))).toBe(' a|+b\nc');
    });
});

describe('the size guard', () => {
    /*
     | The table is `a.length × b.length` cells and the loop that fills it is
     | synchronous, so without a bound a long enough note would freeze the tab.
     | Past the bound the answer degrades to "all of this became all of that",
     | which is true, useful and instant.
     */
    it('degrades to a wholesale replacement rather than allocating a huge table', () => {
        const lines = Math.ceil(Math.sqrt(MAX_DIFF_CELLS)) + 10;
        const before = Array.from({ length: lines }, (_, at) => `line ${at}`).join('\n');
        const after = `${before}\nand one more`;

        const ops = diffLines(before, after);

        expect(ops).toHaveLength(2);
        expect(ops[0]?.kind).toBe('removed');
        expect(ops[1]?.kind).toBe('added');
    });

    it('returns quickly for a large comparison', () => {
        const lines = 4_000;
        const before = Array.from({ length: lines }, (_, at) => `line ${at}`).join('\n');

        const started = Date.now();
        diffLines(before, `changed\n${before}`);

        expect(Date.now() - started).toBeLessThan(1_000);
    });

    it('says nothing changed when nothing did, however large', () => {
        const big = Array.from({ length: 5_000 }, (_, at) => `line ${at}`).join('\n');

        expect(hasChanged(big, big)).toBe(false);
        expect(diffLines(big, big)).toEqual([{ kind: 'same', text: big }]);
    });
});
