/**
 * The decrypted pin store: whose public keys this user has verified.
 *
 * Small, but it holds the state that every fingerprint decision is made against,
 * so it follows the same rules as the vault store in `vault.ts`:
 *
 *  1. **Wiped synchronously on lock**, via `onLock` rather than a watcher. The
 *     pins are plaintext derived from the User Key and have no business
 *     outliving it by a tick.
 *  2. **Failing closed.** When the store could not be loaded, `verdictFor`
 *     answers `unknown` rather than `match`: an unreadable pin store must
 *     produce a verification prompt, never a silent accept. Losing a pin costs
 *     someone thirty seconds; inventing one costs them the property the whole
 *     mechanism exists to provide.
 *
 * Writes are pushed to the server through `persist`, which the caller awaits, so
 * a verification the user was shown as accepted is one that survived the round
 * trip.
 */
import { computed, reactive, readonly } from 'vue';

import type { CryptoClient } from '@/crypto/worker/client';
import { postJson } from '@/lib/http';
import { checkPin, openPins, sealPins, withPin, type PinMap, type PinVerdict } from '@/lib/pins';
import { onLock } from './lock';

/** The pin store as the server holds it: a blob and a concurrency token. */
export interface PinStoreRecord {
    pinsCt: string | null;
    version: number;
}

const state = reactive<{
    pins: PinMap;
    version: number;
    loaded: boolean;
    failure: string;
}>({
    pins: {},
    version: 0,
    loaded: false,
    failure: '',
});

onLock(() => wipe());

export function wipe(): void {
    state.pins = {};
    state.version = 0;
    state.loaded = false;
    state.failure = '';
}

/**
 * Decrypts the stored pins, or records why it could not.
 *
 * A user who has never verified anyone has no row at all, which is not a
 * failure — it is an empty store, and it loads as one.
 */
export async function load(client: CryptoClient, ownerUuid: string, record: PinStoreRecord): Promise<void> {
    if (record.pinsCt === null) {
        state.pins = {};
        state.version = record.version;
        state.loaded = true;
        state.failure = '';

        return;
    }

    try {
        state.pins = await openPins(client, ownerUuid, record.pinsCt);
        state.version = record.version;
        state.loaded = true;
        state.failure = '';
    } catch {
        /*
         | Deliberately not rethrown, and deliberately not treated as an empty
         | store either. `loaded` stays false, which makes `verdictFor` report
         | every identity as unverified — so the user is asked to check rather
         | than told everything is fine on the strength of a store nobody could
         | read.
         */
        wipe();
        state.failure =
            'Your list of verified identities could not be read, so every fingerprint below needs ' +
            'checking again.';
    }
}

/**
 * What is known about an identity's fingerprint.
 *
 * `unknown` when the store failed to load, because the alternative — answering
 * `match` from a store that is empty for the wrong reason — turns a hard stop
 * into a silent accept.
 */
export function verdictFor(userUuid: string, fingerprint: string): PinVerdict {
    if (!state.loaded) {
        return { status: 'unknown' };
    }

    return checkPin(state.pins, userUuid, fingerprint);
}

/**
 * Records that the user has verified an identity, and stores it.
 *
 * The local map is only updated once the server has accepted the write. A pin
 * held in this tab but absent from the account would mean the next device — the
 * one that has not yet been fooled — quietly trusting something on the strength
 * of a decision it never saw.
 */
export async function trust(
    client: CryptoClient,
    ownerUuid: string,
    userUuid: string,
    fingerprint: string,
): Promise<void> {
    const pins = withPin(state.pins, userUuid, fingerprint);

    const { version } = await postJson<{ version: number }>('/account/pins', {
        pins_ct: await sealPins(client, ownerUuid, pins),
        expected_version: state.version,
    });

    state.pins = pins;
    state.version = version;
    state.loaded = true;
}

export function usePins() {
    return {
        state: readonly(state),
        loaded: computed(() => state.loaded),
        failure: computed(() => state.failure),
        verdictFor,
        trust,
    };
}
