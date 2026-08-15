/**
 * The unlock state machine.
 *
 *   anonymous ──login──> locked ──unlock──> unlocked
 *       ▲                   ▲                   │
 *       └──── logout ───────┴─── lock ──────────┘
 *
 * Two states that are easy to conflate and must not be: **authenticated** means
 * the server knows who you are and you hold a session cookie; **unlocked** means
 * your browser holds the User Key. You can be authenticated and locked. You can
 * never be unlocked without being authenticated.
 *
 * Locking terminates the crypto Worker, which is the only erasure of key
 * material a garbage-collected runtime actually guarantees.
 */
import { computed, reactive, readonly } from 'vue';

import { CryptoClient } from '@/crypto/worker/client';
import type { AadParams } from '@/crypto/aad';
import type { KdfParams } from '@/crypto/primitives';
import { fromBase64 } from '@/lib/bytes';
import { describeError } from '@/lib/errors';
import { loadIdentity } from '@/lib/items';

export type SessionStatus = 'anonymous' | 'locked' | 'unlocked';

export type LockReason = 'manual' | 'idle' | 'hidden' | 'navigation' | 'error';

/** Fifteen minutes. Long enough to work, short enough to matter. */
export const IDLE_TIMEOUT_MS = 15 * 60 * 1000;

export interface UnlockBundle {
    kdfSalt: string;
    kdfParams: KdfParams;
    wrappedUserKey: string;
    userKeyAad: AadParams;
}

/**
 * The identity keys, as the server stores them. The private halves are
 * encrypted under the User Key, so they are only useful once unlocked.
 */
export interface IdentityBundle {
    x25519PublicKey: string;
    x25519PrivateKeyCt: string;
    fingerprint: string;
}

const state = reactive<{
    status: SessionStatus;
    lockReason: LockReason | null;
    unlocking: boolean;
}>({
    status: 'anonymous',
    lockReason: null,
    unlocking: false,
});

let client: CryptoClient | null = null;
let idleTimer: ReturnType<typeof setTimeout> | null = null;
let detach: (() => void) | null = null;

/**
 * Anything holding decrypted data, to be told the moment it stops being
 * allowed to.
 *
 * Deliberately a synchronous callback list rather than a watcher on the
 * reactive status. A Vue watcher fires on the next tick, and "the plaintext is
 * gone" must not be true one tick after the user asked for it — between those
 * two moments a screenshot, a devtools snapshot or a render still has the
 * secrets in it. Locking calls these before it returns.
 */
const lockListeners = new Set<() => void>();

/**
 * Registers a listener to be called synchronously on every lock. Returns a
 * function that removes it.
 */
export function onLock(listener: () => void): () => void {
    lockListeners.add(listener);

    return () => lockListeners.delete(listener);
}

/** Test seam: lets a suite supply a client that does not spawn a real Worker. */
let createClient: () => CryptoClient = () => new CryptoClient();

export function setCryptoClientFactory(factory: () => CryptoClient): void {
    createClient = factory;
}

function crypto(): CryptoClient {
    client ??= createClient();

    return client;
}

function clearIdleTimer(): void {
    if (idleTimer !== null) {
        clearTimeout(idleTimer);
        idleTimer = null;
    }
}

function startIdleTimer(): void {
    clearIdleTimer();

    idleTimer = setTimeout(() => lock('idle'), IDLE_TIMEOUT_MS);
}

/** Called on real user activity, so an idle timeout means genuinely idle. */
export function touch(): void {
    if (state.status === 'unlocked') {
        startIdleTimer();
    }
}

/**
 * Confirms the crypto Worker can actually start, before anything depends on it.
 *
 * Worth its own call because the Worker is load-bearing and its failures are
 * environmental — a cross-origin URL, a Content-Security-Policy that names
 * `worker-src` but not `child-src`, a missing build. Discovering that at the
 * moment a user submits their master password is both the worst time and the
 * least informative, so pages that are about to need it ask first.
 *
 * Returns null when the Worker is healthy, or a message to show when it is not.
 */
export async function checkCryptoWorker(): Promise<string | null> {
    try {
        await crypto().status();

        return null;
    } catch (cause) {
        return describeError(cause, 'The cryptographic worker is unavailable.');
    }
}

export function markAuthenticated(): void {
    if (state.status === 'anonymous') {
        state.status = 'locked';
        state.lockReason = null;
    }
}

/**
 * Unlocks, and loads the identity private keys in the same step.
 *
 * Deliberately one operation rather than two. Every vault key arrives as a
 * sealed box addressed to the X25519 key, so an "unlocked" state that could not
 * open one would be a state where nothing readable is readable — a distinction
 * with no use and plenty of room for a bug.
 */
export async function unlock(
    password: string,
    bundle: UnlockBundle,
    identity: IdentityBundle | null,
): Promise<void> {
    state.unlocking = true;

    try {
        const client = crypto();

        await client.unlock({
            op: 'unlock',
            password,
            kdfSalt: fromBase64(bundle.kdfSalt),
            kdfParams: bundle.kdfParams,
            wrappedUserKey: fromBase64(bundle.wrappedUserKey),
            userKeyAad: bundle.userKeyAad,
        });

        if (identity) {
            await loadIdentity(client, bundle.userKeyAad.subject, identity.x25519PrivateKeyCt);
        }

        state.status = 'unlocked';
        state.lockReason = null;
        startIdleTimer();
    } finally {
        state.unlocking = false;
    }
}

export function lock(reason: LockReason = 'manual'): void {
    clearIdleTimer();
    client?.terminate();
    client = null;

    /*
     | Before the status changes, so nothing can observe a store that still
     | holds plaintext while the interface already says "locked" — and before
     | this function returns, so `lock()` really does mean it.
     */
    for (const listener of lockListeners) {
        listener();
    }

    if (state.status !== 'anonymous') {
        state.status = 'locked';
    }

    state.lockReason = reason;
}

export function signOut(): void {
    lock('manual');
    state.status = 'anonymous';
    state.lockReason = null;
}

/**
 * Attaches the automatic lock triggers. Returns a detach function, and is safe
 * to call more than once.
 */
export function installLockGuards(target: Window = window): () => void {
    detach?.();

    const onActivity = () => touch();
    const onVisibility = () => {
        if (target.document.visibilityState === 'hidden') {
            // Not an immediate lock: switching tabs to read a code and coming
            // back would be intolerable. The idle timer keeps running.
            touch();
        }
    };
    const onPageHide = () => lock('navigation');

    const activityEvents = ['pointerdown', 'keydown', 'scroll'] as const;

    for (const event of activityEvents) {
        target.addEventListener(event, onActivity, { passive: true });
    }

    target.document.addEventListener('visibilitychange', onVisibility);
    target.addEventListener('pagehide', onPageHide);

    detach = () => {
        for (const event of activityEvents) {
            target.removeEventListener(event, onActivity);
        }

        target.document.removeEventListener('visibilitychange', onVisibility);
        target.removeEventListener('pagehide', onPageHide);
        detach = null;
    };

    return detach;
}

/** Test seam: resets module state between cases. */
export function resetSession(): void {
    detach?.();
    clearIdleTimer();
    client?.terminate();
    client = null;

    for (const listener of lockListeners) {
        listener();
    }

    state.status = 'anonymous';
    state.lockReason = null;
    state.unlocking = false;
}

export function useSession() {
    return {
        state: readonly(state),
        isUnlocked: computed(() => state.status === 'unlocked'),
        isLocked: computed(() => state.status === 'locked'),
        unlock,
        lock,
        signOut,
        touch,
        markAuthenticated,
        crypto,
    };
}
