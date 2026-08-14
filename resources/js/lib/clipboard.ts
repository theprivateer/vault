/**
 * Copying a secret, and taking it back.
 *
 * The clipboard is shared with every application on the machine and, on some
 * platforms, with other devices. Leaving a password there indefinitely undoes a
 * good deal of the care taken everywhere else, so a copy here has a deadline.
 *
 * Honest about the limits: the clear only happens while this tab is alive, it
 * cannot reach a clipboard history or a synced device, and anything that read
 * the clipboard in the meantime has already read it. It shortens the window; it
 * does not close it.
 */
export const CLIPBOARD_TTL_MS = 30_000;

let pending: ReturnType<typeof setTimeout> | null = null;
let lastCopied: string | null = null;

export interface ClipboardTarget {
    writeText(text: string): Promise<void>;
    readText?(): Promise<string>;
}

/**
 * Copies a value and schedules its removal.
 *
 * The clipboard is only cleared if it still holds what we put there, so a later
 * copy by the user or another application is never wiped out from under them.
 */
export async function copyForATime(
    value: string,
    clipboard: ClipboardTarget = navigator.clipboard,
    ttlMs: number = CLIPBOARD_TTL_MS,
): Promise<void> {
    await clipboard.writeText(value);

    lastCopied = value;

    if (pending !== null) {
        clearTimeout(pending);
    }

    pending = setTimeout(() => {
        void clearIfUnchanged(clipboard);
    }, ttlMs);
}

async function clearIfUnchanged(clipboard: ClipboardTarget): Promise<void> {
    pending = null;

    const copied = lastCopied;
    lastCopied = null;

    if (copied === null) {
        return;
    }

    try {
        // Reading requires permission the user may not have granted. Without
        // it, overwrite unconditionally rather than leaving a password behind.
        const current = await clipboard.readText?.();

        if (current === undefined || current === copied) {
            await clipboard.writeText('');
        }
    } catch {
        /*
         | A denied permission or a background tab. Not worth surfacing: the
         | copy succeeded, only the tidying failed, and there is nothing the
         | user could usefully do about it.
         */
    }
}

/** Test seam, and what a lock should call: forget any scheduled clear. */
export function cancelScheduledClear(): void {
    if (pending !== null) {
        clearTimeout(pending);
        pending = null;
    }

    lastCopied = null;
}
