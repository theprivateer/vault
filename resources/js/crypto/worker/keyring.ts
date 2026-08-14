/**
 * The keyring: the only place in the application where key bytes live.
 *
 * Kept as a plain, testable object rather than module-level state so the Worker
 * glue stays trivial and this logic can be exercised directly.
 */
import type { AadParams } from '../aad';
import { open, seal } from '../envelope';
import { KeyUnavailableError } from '../errors';
import { deriveFromPassword, unwrapKey } from '../keys';
import type { KdfParams } from '../primitives';
import { zeroise } from '../primitives';
import type { KeyHandle } from './protocol';
import { USER_KEY } from './protocol';

export interface UnlockRequest {
    password: string;
    kdfSalt: Uint8Array;
    kdfParams: KdfParams;
    wrappedUserKey: Uint8Array;
    userKeyAad: AadParams;
}

export class Keyring {
    private readonly keys = new Map<KeyHandle, Uint8Array>();

    get unlocked(): boolean {
        return this.keys.has(USER_KEY);
    }

    /** Handles only. Never the bytes behind them. */
    get handles(): KeyHandle[] {
        return [...this.keys.keys()].sort();
    }

    /**
     * Derives the KEK from the password and uses it to unwrap the User Key.
     *
     * The KEK is discarded immediately: it is only ever needed to unwrap, and
     * keeping it alive would widen the window in which a memory disclosure is
     * catastrophic rather than merely bad.
     */
    unlock({ password, kdfSalt, kdfParams, wrappedUserKey, userKeyAad }: UnlockRequest): void {
        this.lock();

        const { kek, authKey } = deriveFromPassword(password, kdfSalt, kdfParams);

        try {
            this.keys.set(USER_KEY, unwrapKey(kek, wrappedUserKey, userKeyAad));
        } finally {
            zeroise(kek, authKey);
        }
    }

    /**
     * Unwraps a key with a key already held, and stores the result under a new
     * handle. This is how the hierarchy is walked without any of it surfacing:
     * User Key → vault keys → item keys.
     */
    unwrapInto(handle: KeyHandle, using: KeyHandle, wrapped: Uint8Array, aad: AadParams): void {
        const unwrapped = unwrapKey(this.require(using), wrapped, aad);

        this.forget(handle);
        this.keys.set(handle, unwrapped);
    }

    seal(handle: KeyHandle, plaintext: Uint8Array, aad: AadParams): Uint8Array {
        return seal(this.require(handle), plaintext, aad);
    }

    open(handle: KeyHandle, envelope: Uint8Array, aad: AadParams): Uint8Array {
        return open(this.require(handle), envelope, aad);
    }

    forget(handle: KeyHandle): void {
        const key = this.keys.get(handle);

        if (key) {
            zeroise(key);
            this.keys.delete(handle);
        }
    }

    /**
     * Zeroises and drops everything.
     *
     * Best-effort in a garbage-collected runtime — terminating the Worker is the
     * only reliable erasure, and that is what the lock action does in the UI.
     * This makes the window smaller for everything that reuses the Worker.
     */
    lock(): void {
        for (const key of this.keys.values()) {
            zeroise(key);
        }

        this.keys.clear();
    }

    private require(handle: KeyHandle): Uint8Array {
        const key = this.keys.get(handle);

        if (!key) {
            throw new KeyUnavailableError(
                `No key is held for "${handle}". The vault may be locked, or the key was never unwrapped.`,
            );
        }

        return key;
    }
}
