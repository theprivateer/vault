import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { CryptoClient } from '@/crypto/worker/client';
import { toBase64 } from '@/lib/bytes';
import {
    IDLE_TIMEOUT_MS,
    installLockGuards,
    lock,
    markAuthenticated,
    resetSession,
    setCryptoClientFactory,
    signOut,
    touch,
    unlock,
    useSession,
} from './session';

const bundle = {
    kdfSalt: toBase64(new Uint8Array(16).fill(1)),
    kdfParams: { m: 8, t: 1, p: 1 },
    wrappedUserKey: toBase64(new Uint8Array(74).fill(2)),
    userKeyAad: {
        context: 'user.userkey',
        subject: '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f6',
        version: 1,
    },
} as const;

function fakeClient() {
    const calls = { unlock: 0, terminate: 0 };
    const client = {
        unlock: vi.fn(() => {
            calls.unlock++;

            return Promise.resolve();
        }),
        terminate: vi.fn(() => {
            calls.terminate++;
        }),
    };

    setCryptoClientFactory(() => client as unknown as CryptoClient);

    return { client, calls };
}

/** A window/document stand-in, so the guards can be exercised under node. */
function fakeWindow() {
    const listeners = new Map<string, Set<EventListener>>();
    const documentListeners = new Map<string, Set<EventListener>>();

    const add = (map: Map<string, Set<EventListener>>) => (type: string, handler: EventListener) => {
        map.set(type, (map.get(type) ?? new Set()).add(handler));
    };

    const remove = (map: Map<string, Set<EventListener>>) => (type: string, handler: EventListener) => {
        map.get(type)?.delete(handler);
    };

    const target = {
        addEventListener: add(listeners),
        removeEventListener: remove(listeners),
        document: {
            visibilityState: 'visible' as DocumentVisibilityState,
            addEventListener: add(documentListeners),
            removeEventListener: remove(documentListeners),
        },
    };

    return {
        target: target as unknown as Window,
        fire: (type: string) => listeners.get(type)?.forEach((handler) => handler(new Event(type))),
        fireDocument: (type: string) =>
            documentListeners.get(type)?.forEach((handler) => handler(new Event(type))),
        count: (type: string) => listeners.get(type)?.size ?? 0,
        documentCount: (type: string) => documentListeners.get(type)?.size ?? 0,
    };
}

beforeEach(() => {
    vi.useFakeTimers();
    resetSession();
    fakeClient();
});

afterEach(() => {
    resetSession();
    vi.useRealTimers();
});

describe('state machine', () => {
    it('starts anonymous', () => {
        expect(useSession().state.status).toBe('anonymous');
    });

    /*
     | Authenticated and unlocked are different things, and conflating them is
     | the mistake this store exists to prevent. Logging in gets you a session;
     | it does not get you a User Key.
     */
    it('authenticating leaves the vault locked', () => {
        markAuthenticated();

        const { state, isLocked, isUnlocked } = useSession();

        expect(state.status).toBe('locked');
        expect(isLocked.value).toBe(true);
        expect(isUnlocked.value).toBe(false);
    });

    it('unlocks with a password and bundle', async () => {
        markAuthenticated();
        await unlock('correct horse', bundle, null);

        expect(useSession().state.status).toBe('unlocked');
    });

    it('clears the unlocking flag even when unlocking fails', async () => {
        const client = { unlock: vi.fn(() => Promise.reject(new Error('bad password'))), terminate: vi.fn() };
        setCryptoClientFactory(() => client as unknown as CryptoClient);

        await expect(unlock('wrong', bundle, null)).rejects.toThrow('bad password');

        expect(useSession().state.unlocking).toBe(false);
        expect(useSession().state.status).not.toBe('unlocked');
    });

    it('locking terminates the worker and records why', async () => {
        const { calls } = fakeClient();
        markAuthenticated();
        await unlock('correct horse', bundle, null);

        lock('idle');

        const { state } = useSession();

        expect(calls.terminate).toBe(1);
        expect(state.status).toBe('locked');
        expect(state.lockReason).toBe('idle');
    });

    it('signing out returns to anonymous', async () => {
        markAuthenticated();
        await unlock('correct horse', bundle, null);

        signOut();

        expect(useSession().state.status).toBe('anonymous');
        expect(useSession().state.lockReason).toBeNull();
    });

    it('locking while anonymous does not fabricate a session', () => {
        lock('manual');

        expect(useSession().state.status).toBe('anonymous');
    });
});

describe('idle locking', () => {
    it('locks after the idle timeout', async () => {
        markAuthenticated();
        await unlock('correct horse', bundle, null);

        vi.advanceTimersByTime(IDLE_TIMEOUT_MS - 1);
        expect(useSession().state.status).toBe('unlocked');

        vi.advanceTimersByTime(1);

        expect(useSession().state.status).toBe('locked');
        expect(useSession().state.lockReason).toBe('idle');
    });

    it('activity postpones the timeout', async () => {
        markAuthenticated();
        await unlock('correct horse', bundle, null);

        vi.advanceTimersByTime(IDLE_TIMEOUT_MS - 1000);
        touch();
        vi.advanceTimersByTime(IDLE_TIMEOUT_MS - 1000);

        expect(useSession().state.status).toBe('unlocked');
    });

    it('ignores activity while locked, so a locked vault stays locked', () => {
        markAuthenticated();
        touch();

        vi.advanceTimersByTime(IDLE_TIMEOUT_MS * 2);

        expect(useSession().state.status).toBe('locked');
    });
});

describe('lock guards', () => {
    it('attaches and detaches its listeners', () => {
        const window = fakeWindow();

        const detach = installLockGuards(window.target);

        expect(window.count('pointerdown')).toBe(1);
        expect(window.count('keydown')).toBe(1);
        expect(window.count('scroll')).toBe(1);
        expect(window.count('pagehide')).toBe(1);
        expect(window.documentCount('visibilitychange')).toBe(1);

        detach();

        expect(window.count('pointerdown')).toBe(0);
        expect(window.documentCount('visibilitychange')).toBe(0);
    });

    it('does not accumulate listeners when installed twice', () => {
        const window = fakeWindow();

        installLockGuards(window.target);
        installLockGuards(window.target);

        expect(window.count('pointerdown')).toBe(1);
    });

    it('locks on pagehide', async () => {
        const window = fakeWindow();
        markAuthenticated();
        await unlock('correct horse', bundle, null);
        installLockGuards(window.target);

        window.fire('pagehide');

        expect(useSession().state.status).toBe('locked');
        expect(useSession().state.lockReason).toBe('navigation');
    });

    it('postpones the timeout on activity', async () => {
        const window = fakeWindow();
        markAuthenticated();
        await unlock('correct horse', bundle, null);
        installLockGuards(window.target);

        vi.advanceTimersByTime(IDLE_TIMEOUT_MS - 1000);
        window.fire('keydown');
        vi.advanceTimersByTime(IDLE_TIMEOUT_MS - 1000);

        expect(useSession().state.status).toBe('unlocked');
    });

    /*
     | Hiding the tab does not lock immediately: switching away to read a code
     | and coming back would be intolerable. The idle timer keeps running.
     */
    it('does not lock immediately when the tab is hidden', async () => {
        const window = fakeWindow();
        markAuthenticated();
        await unlock('correct horse', bundle, null);
        installLockGuards(window.target);

        window.fireDocument('visibilitychange');

        expect(useSession().state.status).toBe('unlocked');
    });
});
