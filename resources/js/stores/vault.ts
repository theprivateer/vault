/**
 * The decrypted contents of the vault currently open, and the search index
 * over them.
 *
 * This is the only long-lived plaintext in the application, which makes it the
 * one structure whose lifetime has to be exactly right. Three rules shape it:
 *
 *  1. **It is wiped synchronously on lock.** It subscribes to `onLock` rather
 *     than watching the reactive status, because a watcher fires next tick and
 *     "locked" has to mean the plaintext is already gone.
 *  2. **It never holds two vaults at once.** Opening a different vault drops
 *     the previous one first, so a stale entry from a vault the user has
 *     navigated away from cannot surface in a search result.
 *  3. **In-flight work is fenced.** A decrypt that was running when the vault
 *     locked resolves *after* the wipe, and writing its results in would
 *     silently repopulate a store that is supposed to be empty. Every run
 *     carries a generation number and results from a stale generation are
 *     discarded.
 *
 * Written as a module-level reactive object, matching the session store. Pinia
 * would be the conventional choice and would add a dependency for a global
 * this project already has exactly two of; the wiping and fencing above are the
 * hard parts, and no store library does them for you.
 */
import { computed, reactive, readonly, shallowRef, type Ref } from 'vue';

import type { CryptoClient } from '@/crypto/worker/client';
import { openAll, openVault, type Opened, type ProgressCallback } from '@/lib/decrypt';
import type {
    EncryptedItem,
    LockboxPayload,
    LockboxRecord,
    SecretPayload,
    SecretRecord,
    VaultPayload,
    VaultRecord,
} from '@/lib/items';
import { buildIndex, EMPTY_INDEX, search, type Indexable, type SearchIndex } from '@/lib/search';
import { onLock } from '@/stores/lock';

export type OpenedLockbox = Opened<LockboxRecord, LockboxPayload>;
export type OpenedSecret = Opened<SecretRecord, SecretPayload>;

export interface VaultContents {
    vault: Opened<VaultRecord, VaultPayload> | null;
    lockboxes: OpenedLockbox[];
    secrets: OpenedSecret[];
}

/** What the caller hands over: the ciphertext exactly as the server sent it. */
export interface VaultSource {
    vault: VaultRecord;
    lockboxes: readonly LockboxRecord[];
    secrets: readonly SecretRecord[];
}

const state = reactive<{
    vaultUuid: string | null;
    contents: VaultContents;
    /** Items decrypted so far in the current run, and how many there are. */
    progress: { done: number; total: number };
    busy: boolean;
    failure: string;
}>({
    vaultUuid: null,
    contents: { vault: null, lockboxes: [], secrets: [] },
    progress: { done: 0, total: 0 },
    busy: false,
    failure: '',
});

/**
 * The index is a Map of Maps, which Vue would deep-proxy for no benefit — it is
 * replaced wholesale, never mutated in place, and proxying every posting list
 * would cost more than building the index does.
 */
const index: Ref<SearchIndex> = shallowRef(EMPTY_INDEX);

/**
 * Plaintext already recovered, keyed by uuid, valid only while the ciphertext
 * it came from is unchanged.
 *
 * This is what makes navigation and optimistic updates cheap: a reload that
 * changes one secret re-decrypts one secret rather than a thousand. Keying on
 * the ciphertext rather than on `updated_at` is deliberate — the server
 * supplies both, and only one of them cannot be lied about in a way that
 * matters, since a different ciphertext always means a real re-decrypt.
 */
const cache = new Map<string, { payloadCt: string; opened: Opened<never, unknown> }>();

/**
 * Incremented by every wipe. A run that started before a wipe finds its
 * generation stale and throws its results away.
 */
let generation = 0;

/** Synchronous, and registered once for the lifetime of the module. */
onLock(() => wipe());

export function wipe(): void {
    generation++;

    state.vaultUuid = null;
    state.contents = { vault: null, lockboxes: [], secrets: [] };
    state.progress = { done: 0, total: 0 };
    state.busy = false;
    state.failure = '';

    cache.clear();
    index.value = EMPTY_INDEX;
}

function cached<R extends EncryptedItem, P>(record: R): Opened<R, P> | null {
    const entry = cache.get(record.uuid);

    if (!entry || entry.payloadCt !== record.payloadCt) {
        return null;
    }

    return entry.opened as unknown as Opened<R, P>;
}

function remember<R extends EncryptedItem, P>(opened: Opened<R, P>): void {
    cache.set(opened.record.uuid, {
        payloadCt: opened.record.payloadCt,
        opened: opened as unknown as Opened<never, unknown>,
    });
}

/**
 * Decrypts a list, reusing anything whose ciphertext has not changed.
 *
 * Failures are cached too. Re-attempting a record that just failed to verify
 * would produce the same failure at the same cost on every reload, and a page
 * that gets slower the more corrupt it is would be a strange thing to build.
 */
async function openWithCache<R extends EncryptedItem, P>(
    client: CryptoClient,
    vaultUuid: string,
    context: Parameters<typeof openAll>[2],
    records: readonly R[],
    label: string,
    onProgress: ProgressCallback,
): Promise<Array<Opened<R, P>>> {
    const known = new Map<string, Opened<R, P>>();
    const missing: R[] = [];

    for (const record of records) {
        const hit = cached<R, P>(record);

        if (hit) {
            known.set(record.uuid, hit);
        } else {
            missing.push(record);
        }
    }

    const opened = await openAll<R, P>(
        client,
        vaultUuid,
        context,
        missing,
        () => label,
        (done, total) => onProgress(done + known.size, total + known.size),
    );

    for (const entry of opened) {
        known.set(entry.record.uuid, entry);
        remember(entry);
    }

    // Back into the order the server sent, which is the order the interface
    // renders — the cache must not reshuffle a list.
    return records.map((record) => known.get(record.uuid)).filter((entry) => entry !== undefined);
}

/**
 * Decrypts a whole vault into the store.
 *
 * The vault key has to be unwrapped before anything under it, so the first step
 * is sequential by necessity; everything after it is batched.
 */
export async function openContents(client: CryptoClient, source: VaultSource): Promise<void> {
    if (state.vaultUuid !== null && state.vaultUuid !== source.vault.uuid) {
        wipe();
    }

    const run = generation;
    const total = source.lockboxes.length + source.secrets.length;

    state.busy = true;
    state.failure = '';
    state.progress = { done: 0, total };

    const report: ProgressCallback = (done) => {
        if (run === generation) {
            state.progress = { done, total };
        }
    };

    try {
        const vault = await openVault<VaultPayload>(client, source.vault);

        if (vault.error) {
            /*
             | Without the Vault Key nothing beneath it can be read, so this is
             | a page-level failure rather than a row-level one. Reporting it as
             | "no lockboxes" would be the 2017 bug in a new costume.
             */
            if (run === generation) {
                state.vaultUuid = source.vault.uuid;
                state.contents = { vault, lockboxes: [], secrets: [] };
                state.failure = vault.error;
            }

            return;
        }

        const lockboxes = await openWithCache<LockboxRecord, LockboxPayload>(
            client,
            source.vault.uuid,
            'lockbox.payload',
            source.lockboxes,
            'This lockbox',
            report,
        );

        const secrets = await openWithCache<SecretRecord, SecretPayload>(
            client,
            source.vault.uuid,
            'secret.payload',
            source.secrets,
            'This secret',
            (done) => report(done + lockboxes.length, total),
        );

        // The fence. A lock during the awaits above already emptied the store,
        // and this is what stops the results refilling it.
        if (run !== generation) {
            return;
        }

        state.vaultUuid = source.vault.uuid;
        state.contents = { vault, lockboxes, secrets };
        index.value = buildIndex(indexable(lockboxes, secrets));
        state.progress = { done: total, total };
    } finally {
        if (run === generation) {
            state.busy = false;
        }
    }
}

/**
 * Builds the search documents.
 *
 * Secret values are not among them, on purpose: nobody searches for a password
 * by typing it, and an index over values would be a second copy of every
 * credential with its own lifetime to get wrong. See the note in lib/search.ts.
 */
function indexable(lockboxes: readonly OpenedLockbox[], secrets: readonly OpenedSecret[]): Indexable[] {
    const names = new Map(
        lockboxes.flatMap((entry) => (entry.payload ? [[entry.record.uuid, entry.payload.name]] : [])),
    );

    return [
        ...lockboxes.flatMap<Indexable>((entry) =>
            entry.payload
                ? [
                      {
                          id: entry.record.uuid,
                          fields: { name: entry.payload.name, notes: entry.payload.description },
                      },
                  ]
                : [],
        ),
        ...secrets.flatMap<Indexable>((entry) =>
            entry.payload
                ? [
                      {
                          id: entry.record.uuid,
                          fields: {
                              name: entry.payload.key,
                              notes: entry.payload.notes,
                              url: entry.payload.url ?? '',
                              type: entry.payload.type,
                              location: names.get(entry.record.lockboxUuid) ?? '',
                          },
                      },
                  ]
                : [],
        ),
    ];
}

/**
 * Writes a decrypted item into the store before the server has confirmed it.
 *
 * The plaintext is already in hand — the client encrypted it a moment ago — so
 * there is nothing to guess at and nothing to reconcile. What this buys is an
 * interface that responds at the speed of typing rather than the speed of a
 * round trip, and the rollback below is what keeps that honest.
 *
 * Returns a function that undoes it exactly, for the failure path.
 */
export function applyOptimistic(secret: OpenedSecret): () => void {
    const existing = state.contents.secrets.findIndex((entry) => entry.record.uuid === secret.record.uuid);
    const previous = existing === -1 ? null : state.contents.secrets[existing];
    const secrets = [...state.contents.secrets];

    if (existing === -1) {
        secrets.push(secret);
    } else {
        secrets[existing] = secret;
    }

    state.contents = { ...state.contents, secrets };
    reindex();

    return () => {
        const rolled = [...state.contents.secrets];
        const at = rolled.findIndex((entry) => entry.record.uuid === secret.record.uuid);

        if (at === -1) {
            return;
        }

        if (previous) {
            rolled[at] = previous;
        } else {
            rolled.splice(at, 1);
        }

        state.contents = { ...state.contents, secrets: rolled };
        cache.delete(secret.record.uuid);
        reindex();
    };
}

/** Removes an item optimistically, returning the undo. */
export function removeOptimistic(uuid: string): () => void {
    const at = state.contents.secrets.findIndex((entry) => entry.record.uuid === uuid);

    if (at === -1) {
        return () => {};
    }

    // Non-null: the index came from findIndex on this same array.
    const removed = state.contents.secrets[at]!;
    const secrets = state.contents.secrets.filter((entry) => entry.record.uuid !== uuid);

    state.contents = { ...state.contents, secrets };
    cache.delete(uuid);
    reindex();

    return () => {
        const restored = [...state.contents.secrets];

        restored.splice(at, 0, removed);
        state.contents = { ...state.contents, secrets: restored };
        reindex();
    };
}

function reindex(): void {
    index.value = buildIndex(indexable(state.contents.lockboxes, state.contents.secrets));
}

export function useVaultContents() {
    return {
        state: readonly(state),
        contents: computed(() => state.contents),
        busy: computed(() => state.busy),
        failure: computed(() => state.failure),
        progress: computed(() => state.progress),
        /** True while a first decrypt of a non-trivial vault is under way. */
        showProgress: computed(() => state.busy && state.progress.total > 0),
        secretsIn: (lockboxUuid: string) =>
            state.contents.secrets.filter((entry) => entry.record.lockboxUuid === lockboxUuid),
        find: (query: string) => search(index.value, query),
        openContents,
        applyOptimistic,
        removeOptimistic,
        wipe,
    };
}
