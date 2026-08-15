/**
 * The lock signal, on its own so that everything can depend on it.
 *
 * Anything holding plaintext needs telling the moment it stops being allowed to,
 * and the session store needs to load some of those stores when it unlocks. Left
 * in one module those two facts form an import cycle, and a cycle here is not a
 * stylistic complaint: the subscriber calls `onLock` while its module is being
 * evaluated, so whichever module happened to load second would reach for a
 * binding that does not exist yet and fail at start-up.
 *
 * **Synchronous by design.** A Vue watcher on the reactive status fires on the
 * next tick, and "the plaintext is gone" must not be true one tick after the
 * user asked for it — a screenshot, a devtools snapshot or a render all fit in
 * that gap. `notifyLock` calls every listener before it returns.
 */
const listeners = new Set<() => void>();

/** Registers a listener. Returns a function that removes it. */
export function onLock(listener: () => void): () => void {
    listeners.add(listener);

    return () => listeners.delete(listener);
}

export function notifyLock(): void {
    for (const listener of listeners) {
        listener();
    }
}
