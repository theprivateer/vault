/**
 * The keyring: the only place in the application where key bytes live.
 *
 * Kept as a plain, testable object rather than module-level state so the Worker
 * glue stays trivial and this logic can be exercised directly.
 */
import type { AadContext, AadParams } from '../aad';
import { openChunk, sealChunk } from '../chunks';
import { open, seal } from '../envelope';
import { InvalidParameterError, KeyUnavailableError, MalformedEnvelopeError } from '../errors';
import type { Grant, SignedGrant } from '../grant';
import { signGrant } from '../grant';
import { generateIdentity } from '../identity';
import {
    deriveFromPassword,
    deriveRecoveryKeys,
    generateKey,
    generateRecoveryCode,
    openSealed,
    sealTo,
    unwrapKey,
    wrapKey,
} from '../keys';
import type { KdfParams } from '../primitives';
import { KEY_LENGTH, zeroise } from '../primitives';
import type { BulkOpenItem, ChunkRequest, KeyHandle } from './protocol';
import { ED25519_KEY, USER_KEY, X25519_KEY } from './protocol';

/**
 * Keys that must never be sealed to a public key supplied by a caller.
 *
 * `sealToPublicKey` is the one operation that produces something a party other
 * than this device can open, so it is the one place where injected script could
 * turn "ask the Worker to do things" into "walk away with the account". Sharing
 * needs it for Vault Keys; nothing needs it for these three, so they are
 * refused. It bounds an XSS to the items it explicitly asks for — see adversary
 * A7 in docs/02-threat-model.md.
 */
const UNSEALABLE: readonly KeyHandle[] = [USER_KEY, X25519_KEY, ED25519_KEY];

export interface UnlockRequest {
    password: string;
    kdfSalt: Uint8Array;
    kdfParams: KdfParams;
    wrappedUserKey: Uint8Array;
    userKeyAad: AadParams;
}

export interface RegistrationRequest {
    password: string;
    kdfSalt: Uint8Array;
    kdfParams: KdfParams;
    /** Client-generated, so the AAD can bind before the row exists. */
    uuid: string;
}

export interface RegistrationResult {
    authKey: Uint8Array;
    wrappedUserKey: Uint8Array;
    /** The one secret that must leave the Worker: the user has to write it down. */
    recoveryCode: string;
    recoverySalt: Uint8Array;
    recoveryWrappedUserKey: Uint8Array;
    /** Lets the server verify a recovery attempt without learning the code. */
    recoveryAuthKey: Uint8Array;
    x25519PublicKey: Uint8Array;
    ed25519PublicKey: Uint8Array;
    x25519PrivateKeyCt: Uint8Array;
    ed25519PrivateKeyCt: Uint8Array;
    selfSignature: Uint8Array;
    fingerprint: Uint8Array;
}

export interface SealChunkRequest extends ChunkRequest {
    plaintext: Uint8Array;
}

export interface OpenChunkRequest extends ChunkRequest {
    chunk: Uint8Array;
}

export class Keyring {
    private readonly keys = new Map<KeyHandle, Uint8Array>();

    /**
     * Held between beginUnlock and completeUnlock during login, and at no other
     * time. Discarded the moment the User Key is unwrapped.
     */
    private pendingKek: Uint8Array | null = null;

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
     * Creates a whole account: User Key, identity keypairs, recovery kit.
     *
     * Everything is generated and wrapped in here. What comes back is the
     * ciphertext the server will store, plus the recovery code — which has to
     * leave, because its entire purpose is to be shown to the user once and
     * written down. The User Key and both private keys never do.
     *
     * The account is left unlocked, since the user just proved they know the
     * password by choosing it.
     */
    register({ password, kdfSalt, kdfParams, uuid }: RegistrationRequest): RegistrationResult {
        this.lock();

        const { kek, authKey } = deriveFromPassword(password, kdfSalt, kdfParams);
        const userKey = generateKey();
        const identity = generateIdentity();
        const recovery = generateRecoveryCode();

        const aad = (context: AadContext): AadParams => ({ context, subject: uuid, version: 1 });

        try {
            return {
                authKey,
                wrappedUserKey: wrapKey(kek, userKey, aad('user.userkey')),
                recoveryCode: recovery.formatted,
                recoverySalt: recovery.salt,
                recoveryWrappedUserKey: wrapKey(recovery.kek, userKey, aad('user.userkey')),
                recoveryAuthKey: recovery.authKey,
                x25519PublicKey: identity.x25519.publicKey,
                ed25519PublicKey: identity.ed25519.publicKey,
                x25519PrivateKeyCt: seal(userKey, identity.x25519.secretKey, aad('user.privkey.x25519')),
                ed25519PrivateKeyCt: seal(userKey, identity.ed25519.secretKey, aad('user.privkey.ed25519')),
                selfSignature: identity.selfSignature,
                fingerprint: identity.fingerprint,
            };
        } finally {
            this.keys.set(USER_KEY, userKey);
            zeroise(kek, recovery.kek, identity.x25519.secretKey, identity.ed25519.secretKey);
        }
    }

    /**
     * Step one of recovery, mirroring beginUnlock.
     *
     * Splits the recovery code, retains the KEK, and returns only the auth key
     * for the server to verify. `completeUnlock` finishes the job once the
     * server has handed back the wrapping.
     */
    beginRecovery(recoveryCode: string, recoverySalt: Uint8Array): Uint8Array {
        this.lock();

        const { kek, authKey } = deriveRecoveryKeys(recoveryCode, recoverySalt);

        this.pendingKek = kek;

        return authKey;
    }

    /** Unlocks using the recovery kit instead of the password, in one step. */
    unlockWithRecovery(
        recoveryCode: string,
        recoverySalt: Uint8Array,
        wrappedUserKey: Uint8Array,
        aad: AadParams,
    ): void {
        this.lock();

        const { kek, authKey } = deriveRecoveryKeys(recoveryCode, recoverySalt);

        try {
            this.keys.set(USER_KEY, unwrapKey(kek, wrappedUserKey, aad));
        } finally {
            zeroise(kek, authKey);
        }
    }

    /**
     * Re-wraps the held User Key under a new password.
     *
     * Only the wrapping changes. The User Key itself, the identity keys and
     * every vault key stay exactly as they were — which is the whole reason the
     * User Key indirection exists.
     */
    rewrapForPassword(
        password: string,
        kdfSalt: Uint8Array,
        kdfParams: KdfParams,
        aad: AadParams,
    ): { authKey: Uint8Array; wrappedUserKey: Uint8Array } {
        const userKey = this.require(USER_KEY);
        const { kek, authKey } = deriveFromPassword(password, kdfSalt, kdfParams);

        try {
            return { authKey, wrappedUserKey: wrapKey(kek, userKey, aad) };
        } finally {
            zeroise(kek);
        }
    }

    /** Issues a fresh recovery kit for the currently held User Key. */
    issueRecoveryKit(aad: AadParams): {
        recoveryCode: string;
        recoverySalt: Uint8Array;
        recoveryWrappedUserKey: Uint8Array;
        recoveryAuthKey: Uint8Array;
    } {
        const userKey = this.require(USER_KEY);
        const recovery = generateRecoveryCode();

        try {
            return {
                recoveryCode: recovery.formatted,
                recoverySalt: recovery.salt,
                recoveryWrappedUserKey: wrapKey(recovery.kek, userKey, aad),
                recoveryAuthKey: recovery.authKey,
            };
        } finally {
            zeroise(recovery.kek);
        }
    }

    /**
     * Derives from the password and returns only the auth key.
     *
     * The KEK is retained inside the Worker so the caller can finish unlocking
     * once the server has returned the wrapped User Key, without paying for a
     * second Argon2id run. The auth key is the only thing that leaves.
     */
    beginUnlock(password: string, kdfSalt: Uint8Array, kdfParams: KdfParams): Uint8Array {
        this.lock();

        const { kek, authKey } = deriveFromPassword(password, kdfSalt, kdfParams);

        this.pendingKek = kek;

        return authKey;
    }

    /** Finishes a login begun by beginUnlock, using the retained KEK. */
    completeUnlock(wrappedUserKey: Uint8Array, aad: AadParams): void {
        if (!this.pendingKek) {
            throw new KeyUnavailableError(
                'No unlock is in progress. beginUnlock must be called before completeUnlock.',
            );
        }

        try {
            this.keys.set(USER_KEY, unwrapKey(this.pendingKek, wrappedUserKey, aad));
        } finally {
            this.discardPendingKek();
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

    /**
     * Generates a fresh random key under a handle: a Vault Key or an Item Key.
     *
     * It never leaves. The caller receives nothing at all, and reaches the key
     * only through `seal`, `wrapFrom` and `sealToPublicKey`.
     */
    generateInto(handle: KeyHandle): void {
        this.forget(handle);
        this.keys.set(handle, generateKey());
    }

    /**
     * Wraps one held key under another and returns the ciphertext.
     *
     * Both operands are handles, so this cannot be used to wrap a key under
     * attacker-chosen bytes — the output is only openable by whoever already
     * holds the wrapping key.
     */
    wrapFrom(handle: KeyHandle, using: KeyHandle, aad: AadParams): Uint8Array {
        return wrapKey(this.require(using), this.require(handle), aad);
    }

    /** Seals a held key to a recipient's X25519 public key. */
    sealToPublicKey(handle: KeyHandle, recipientPublicKey: Uint8Array, aad: AadParams): Uint8Array {
        if (UNSEALABLE.includes(handle)) {
            throw new InvalidParameterError(
                `"${handle}" cannot be sealed to another key. Only vault and item keys are shareable.`,
            );
        }

        return sealTo(recipientPublicKey, this.require(handle), aad);
    }

    /**
     * Opens a sealed box with a held private key and stores the result under a
     * new handle. This is how a member's Vault Key is recovered from their
     * membership row.
     */
    openSealedInto(handle: KeyHandle, using: KeyHandle, sealed: Uint8Array, aad: AadParams): void {
        const key = openSealed(this.require(using), sealed, aad);

        if (key.length !== KEY_LENGTH) {
            zeroise(key);

            throw new MalformedEnvelopeError(
                `Sealed value is ${key.length} bytes, expected a ${KEY_LENGTH} byte key.`,
            );
        }

        this.forget(handle);
        this.keys.set(handle, key);
    }

    /**
     * Unwraps an Item Key, opens one payload with it, and zeroises it again.
     *
     * The Item Key is never stored under a handle. Nothing needs it a second
     * time — every write generates a fresh one — so keeping it would mean a
     * keyring that grows by one entry per secret ever displayed, a thousand
     * live keys in a thousand-secret vault, and a correspondingly larger prize
     * for anything that reads Worker memory. Unwrapping it per open costs one
     * ChaCha20 pass over 32 bytes, which is nothing.
     *
     * The `finally` matters: the key is wiped whether the payload verified or
     * not, and an integrity failure is exactly the case where something has
     * gone wrong and the cleanup is most likely to be skipped.
     */
    openWithWrappedKey({ using, wrapped, keyAad, envelope, payloadAad }: BulkOpenItem): Uint8Array {
        const itemKey = unwrapKey(this.require(using), wrapped, keyAad);

        try {
            return open(itemKey, envelope, payloadAad);
        } finally {
            zeroise(itemKey);
        }
    }

    /**
     * Encrypts one chunk of a file under its wrapped File Key.
     *
     * The File Key is unwrapped, used and zeroised per chunk rather than held —
     * see `ChunkRequest`. The `finally` is the same discipline as
     * `openWithWrappedKey`: the key is wiped whether the chunk sealed or not.
     */
    async sealChunk({
        using,
        wrapped,
        keyAad,
        plaintext,
        noncePrefix,
        aad,
    }: SealChunkRequest): Promise<Uint8Array> {
        const fileKey = unwrapKey(this.require(using), wrapped, keyAad);

        try {
            return await sealChunk(fileKey, plaintext, noncePrefix, aad);
        } finally {
            zeroise(fileKey);
        }
    }

    /** Decrypts one chunk. Throws if it came from the wrong file or position. */
    async openChunk({
        using,
        wrapped,
        keyAad,
        chunk,
        noncePrefix,
        aad,
    }: OpenChunkRequest): Promise<Uint8Array> {
        const fileKey = unwrapKey(this.require(using), wrapped, keyAad);

        try {
            return await openChunk(fileKey, chunk, noncePrefix, aad);
        } finally {
            zeroise(fileKey);
        }
    }

    /**
     * Signs a membership grant with the held Ed25519 key.
     *
     * Takes a grant rather than bytes, on purpose. A general signing operation
     * would hand injected script the user's signature on anything the format
     * ever comes to cover, from one foothold; this one can only ever produce a
     * statement about a vault membership, and `signGrant` applies the grant
     * domain separator so the result cannot be replayed as a self-signature or
     * an audit entry.
     */
    signGrant(grant: Grant): SignedGrant {
        return signGrant(this.require(ED25519_KEY), grant);
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
        this.discardPendingKek();
    }

    private discardPendingKek(): void {
        if (this.pendingKek) {
            zeroise(this.pendingKek);
            this.pendingKek = null;
        }
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
