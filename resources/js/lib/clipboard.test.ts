import { afterEach, describe, expect, it, vi } from 'vitest';

import { cancelScheduledClear, copyForATime } from './clipboard';

/** A clipboard that records what it was given. */
function fakeClipboard(readable = true) {
    const writes: string[] = [];
    let contents = '';

    return {
        writes,
        writeText: (text: string) => {
            contents = text;
            writes.push(text);

            return Promise.resolve();
        },
        ...(readable ? { readText: () => Promise.resolve(contents) } : {}),
        set(value: string) {
            contents = value;
        },
    };
}

afterEach(() => {
    cancelScheduledClear();
    vi.useRealTimers();
});

describe('copying a secret', () => {
    it('writes the value immediately', async () => {
        const clipboard = fakeClipboard();

        await copyForATime('hunter2', clipboard, 1_000);

        expect(clipboard.writes).toEqual(['hunter2']);
    });

    it('clears the value once its time is up', async () => {
        vi.useFakeTimers();
        const clipboard = fakeClipboard();

        await copyForATime('hunter2', clipboard, 1_000);
        await vi.advanceTimersByTimeAsync(1_000);

        expect(clipboard.writes).toEqual(['hunter2', '']);
    });

    /*
     | Wiping a clipboard the user has since used for something else would be a
     | small betrayal, and the kind that makes people stop using the copy button.
     */
    it('leaves the clipboard alone if something else has copied since', async () => {
        vi.useFakeTimers();
        const clipboard = fakeClipboard();

        await copyForATime('hunter2', clipboard, 1_000);
        clipboard.set('a shopping list');

        await vi.advanceTimersByTimeAsync(1_000);

        expect(clipboard.writes).toEqual(['hunter2']);
    });

    /*
     | Reading the clipboard needs a permission the user may never have granted.
     | Without it the only safe assumption is that our value is still there.
     */
    it('clears anyway when it cannot read the clipboard back', async () => {
        vi.useFakeTimers();
        const clipboard = fakeClipboard(false);

        await copyForATime('hunter2', clipboard, 1_000);
        await vi.advanceTimersByTimeAsync(1_000);

        expect(clipboard.writes).toEqual(['hunter2', '']);
    });

    it('does not clear a second copy early', async () => {
        vi.useFakeTimers();
        const clipboard = fakeClipboard();

        await copyForATime('first', clipboard, 1_000);
        await vi.advanceTimersByTimeAsync(600);
        await copyForATime('second', clipboard, 1_000);

        // The first copy's deadline has passed, but it was superseded.
        await vi.advanceTimersByTimeAsync(600);
        expect(clipboard.writes).toEqual(['first', 'second']);

        await vi.advanceTimersByTimeAsync(400);
        expect(clipboard.writes).toEqual(['first', 'second', '']);
    });

    it('swallows a clipboard that refuses to be read or written', async () => {
        vi.useFakeTimers();

        const clipboard = {
            writeText: vi.fn(() => Promise.resolve()),
            readText: vi.fn(() => Promise.reject(new Error('permission denied'))),
        };

        await copyForATime('hunter2', clipboard, 1_000);
        await vi.advanceTimersByTimeAsync(1_000);

        // The copy worked; only the tidying failed, and there is nothing the
        // user could do about it.
        expect(clipboard.writeText).toHaveBeenCalledExactlyOnceWith('hunter2');
    });

    it('cancelling stops a pending clear', async () => {
        vi.useFakeTimers();
        const clipboard = fakeClipboard();

        await copyForATime('hunter2', clipboard, 1_000);
        cancelScheduledClear();
        await vi.advanceTimersByTimeAsync(1_000);

        expect(clipboard.writes).toEqual(['hunter2']);
    });
});
