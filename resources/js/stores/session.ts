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

export function markAuthenticated(): void {
    if (state.status === 'anonymous') {
        state.status = 'locked';
        state.lockReason = null;
    }
}

export async function unlock(password: string, bundle: UnlockBundle): Promise<void> {
    state.unlocking = true;

    try {
        await crypto().unlock({
            op: 'unlock',
            password,
            kdfSalt: fromBase64(bundle.kdfSalt),
            kdfParams: bundle.kdfParams,
            wrappedUserKey: fromBase64(bundle.wrappedUserKey),
            userKeyAad: bundle.userKeyAad,
        });

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
