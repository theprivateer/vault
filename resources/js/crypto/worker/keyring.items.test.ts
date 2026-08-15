/**
 * The lower half of the key hierarchy: Vault Key → Item Key → payload.
 *
 * The property under test throughout is that a second Keyring, holding nothing
 * but the password and the blobs a server would have stored, arrives back at
 * the same plaintext — and that every deviation from the exact record a
 * ciphertext was bound to fails instead.
 */
import { describe, expect, it } from 'vitest';

import type { AadParams } from '../aad';
import {
    IntegrityError,
    InvalidParameterError,
    KeyUnavailableError,
    MalformedEnvelopeError,
} from '../errors';
import { verifyGrant } from '../grant';
import { generateKdfSalt, sealTo } from '../keys';
import { utf8ToBytes } from '../primitives';
import type { RegistrationResult } from './keyring';
import { Keyring } from './keyring';
import { ED25519_KEY, USER_KEY, X25519_KEY, itemKeyHandle, vaultKeyHandle } from './protocol';

const FAST_KDF = { m: 8, t: 1, p: 1 };

const USER_UUID = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f6';
const VAULT_UUID = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f7';
const MEMBERSHIP_UUID = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f8';
const OTHER_UUID = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f9';

const aad = (context: AadParams['context'], subject: string): AadParams => ({
    context,
    subject,
    version: 1,
});

const userKeyAad = aad('user.userkey', USER_UUID);
const x25519Aad = aad('user.privkey.x25519', USER_UUID);
const ed25519Aad = aad('user.privkey.ed25519', USER_UUID);
const membershipAad = aad('vault.membership.key', MEMBERSHIP_UUID);
const itemKeyAad = aad('item.key', VAULT_UUID);
const payloadAad = aad('vault.payload', VAULT_UUID);

const VAULT_KEY = vaultKeyHandle(VAULT_UUID);
const ITEM_KEY = itemKeyHandle(VAULT_UUID);

const PAYLOAD = utf8ToBytes(JSON.stringify({ name: 'Production', description: 'live credentials' }));

interface Account {
    password: string;
    kdfSalt: Uint8Array;
    registration: RegistrationResult;
}

/** An unlocked keyring with its identity private keys loaded. */
function openAccount(): { keyring: Keyring; account: Account } {
    const password = 'correct horse battery staple';
    const kdfSalt = generateKdfSalt();
    const keyring = new Keyring();

    const registration = keyring.register({ password, kdfSalt, kdfParams: FAST_KDF, uuid: USER_UUID });

    loadIdentityKeys(keyring, registration);

    return { keyring, account: { password, kdfSalt, registration } };
}

/**
 * Both private keys, as `loadIdentity` does on a real unlock: X25519 opens
 * sealed vault keys, Ed25519 signs grants.
 */
function loadIdentityKeys(keyring: Keyring, registration: RegistrationResult): void {
    keyring.unwrapInto(X25519_KEY, USER_KEY, registration.x25519PrivateKeyCt, x25519Aad);
    keyring.unwrapInto(ED25519_KEY, USER_KEY, registration.ed25519PrivateKeyCt, ed25519Aad);
}

/** Reopens the same account from scratch, as a fresh page load would. */
function reopenAccount(account: Account): Keyring {
    const keyring = new Keyring();

    keyring.unlock({
        password: account.password,
        kdfSalt: account.kdfSalt,
        kdfParams: FAST_KDF,
        wrappedUserKey: account.registration.wrappedUserKey,
        userKeyAad,
    });

    loadIdentityKeys(keyring, account.registration);

    return keyring;
}

/** Everything a server would hold for a newly created vault. */
function createVault(keyring: Keyring, publicKey: Uint8Array) {
    keyring.generateInto(VAULT_KEY);
    keyring.generateInto(ITEM_KEY);

    return {
        payloadCt: keyring.seal(ITEM_KEY, PAYLOAD, payloadAad),
        wrappedItemKey: keyring.wrapFrom(ITEM_KEY, VAULT_KEY, itemKeyAad),
        wrappedVaultKey: keyring.sealToPublicKey(VAULT_KEY, publicKey, membershipAad),
    };
}

describe('the vault key hierarchy', () => {
    it('round-trips a payload through a fresh keyring holding only the stored blobs', () => {
        const { keyring, account } = openAccount();
        const stored = createVault(keyring, account.registration.x25519PublicKey);

        const fresh = reopenAccount(account);

        fresh.openSealedInto(VAULT_KEY, X25519_KEY, stored.wrappedVaultKey, membershipAad);
        fresh.unwrapInto(ITEM_KEY, VAULT_KEY, stored.wrappedItemKey, itemKeyAad);

        expect(fresh.open(ITEM_KEY, stored.payloadCt, payloadAad)).toEqual(PAYLOAD);
    });

    it('generates a different key for every handle', () => {
        const { keyring, account } = openAccount();

        const first = createVault(keyring, account.registration.x25519PublicKey);
        const second = createVault(keyring, account.registration.x25519PublicKey);

        // Same plaintext, same AAD, different keys: the ciphertexts cannot match.
        expect(first.payloadCt).not.toEqual(second.payloadCt);
    });

    it('reports handles without ever exposing the bytes behind them', () => {
        const { keyring, account } = openAccount();
        createVault(keyring, account.registration.x25519PublicKey);

        expect(keyring.handles).toEqual([ED25519_KEY, X25519_KEY, ITEM_KEY, USER_KEY, VAULT_KEY].sort());
    });

    it('forgets a key on request', () => {
        const { keyring, account } = openAccount();
        createVault(keyring, account.registration.x25519PublicKey);

        keyring.forget(ITEM_KEY);

        expect(keyring.handles).not.toContain(ITEM_KEY);
    });
});

describe('associated data binding', () => {
    it('refuses a wrapped item key relocated to another record', () => {
        const { keyring, account } = openAccount();
        const stored = createVault(keyring, account.registration.x25519PublicKey);

        expect(() =>
            keyring.unwrapInto(ITEM_KEY, VAULT_KEY, stored.wrappedItemKey, aad('item.key', OTHER_UUID)),
        ).toThrow(IntegrityError);
    });

    it('refuses a sealed vault key relocated to another membership row', () => {
        const { keyring, account } = openAccount();
        const stored = createVault(keyring, account.registration.x25519PublicKey);

        expect(() =>
            keyring.openSealedInto(
                VAULT_KEY,
                X25519_KEY,
                stored.wrappedVaultKey,
                aad('vault.membership.key', OTHER_UUID),
            ),
        ).toThrow(IntegrityError);
    });

    it('refuses a payload opened under the wrong context', () => {
        const { keyring, account } = openAccount();
        const stored = createVault(keyring, account.registration.x25519PublicKey);

        expect(() => keyring.open(ITEM_KEY, stored.payloadCt, aad('secret.payload', VAULT_UUID))).toThrow(
            IntegrityError,
        );
    });
});

describe('signing grants', () => {
    const grant = {
        vaultUuid: VAULT_UUID,
        recipientUuid: OTHER_UUID,
        recipientFingerprint: 'a'.repeat(64),
        role: 'editor' as const,
        keyEpoch: 1,
        grantedAt: '2026-08-15T09:00:00Z',
    };

    it('signs with the identity key, verifiably by anyone holding the public half', () => {
        const { keyring, account } = openAccount();

        const { payload, signature } = keyring.signGrant(grant);

        expect(verifyGrant(signature, payload, account.registration.ed25519PublicKey, grant)).toMatchObject({
            valid: true,
        });
    });

    /**
     * The Ed25519 key is loaded by unlocking, so this is the state a locked
     * session is in — and a grant signed by nothing would be a grant nobody can
     * verify, which is worse than a refusal.
     */
    it('refuses when no identity key is held', () => {
        expect(() => new Keyring().signGrant(grant)).toThrow(KeyUnavailableError);
    });

    it('refuses to sign a malformed grant rather than committing to nonsense', () => {
        const { keyring } = openAccount();

        expect(() => keyring.signGrant({ ...grant, keyEpoch: 0 })).toThrow(InvalidParameterError);
    });
});

describe('sealing to a public key', () => {
    it.each([USER_KEY, X25519_KEY, ED25519_KEY])('refuses to seal %s to any public key', (handle) => {
        const { keyring, account } = openAccount();

        expect(() =>
            keyring.sealToPublicKey(handle, account.registration.x25519PublicKey, membershipAad),
        ).toThrow(InvalidParameterError);
    });

    it('rejects a sealed value that is not a key', () => {
        const { keyring, account } = openAccount();

        // A well-formed sealed box the recipient can open, carrying something
        // that was never a 32-byte key. The tag verifies, so only the length
        // check stands between this and being used as one.
        const sealed = sealTo(account.registration.x25519PublicKey, utf8ToBytes('not a key'), membershipAad);

        expect(() => keyring.openSealedInto(VAULT_KEY, X25519_KEY, sealed, membershipAad)).toThrow(
            MalformedEnvelopeError,
        );
    });

    it('leaves the target handle untouched when the sealed value is rejected', () => {
        const { keyring, account } = openAccount();

        keyring.generateInto(VAULT_KEY);
        const before = keyring.seal(VAULT_KEY, PAYLOAD, payloadAad);

        const sealed = sealTo(account.registration.x25519PublicKey, utf8ToBytes('not a key'), membershipAad);

        expect(() => keyring.openSealedInto(VAULT_KEY, X25519_KEY, sealed, membershipAad)).toThrow(
            MalformedEnvelopeError,
        );

        // Still the original key: a failed unseal must not blank a live handle.
        expect(keyring.open(VAULT_KEY, before, payloadAad)).toEqual(PAYLOAD);
    });
});

describe('opening with a wrapped key', () => {
    /** The shape a bulk open sends for one item. */
    const bulkItem = (stored: ReturnType<typeof createVault>) => ({
        using: VAULT_KEY,
        wrapped: stored.wrappedItemKey,
        keyAad: itemKeyAad,
        envelope: stored.payloadCt,
        payloadAad,
    });

    it('unwraps, opens and gets back the same plaintext', () => {
        const { keyring, account } = openAccount();
        const stored = createVault(keyring, account.registration.x25519PublicKey);

        const fresh = reopenAccount(account);
        fresh.openSealedInto(VAULT_KEY, X25519_KEY, stored.wrappedVaultKey, membershipAad);

        expect(fresh.openWithWrappedKey(bulkItem(stored))).toEqual(PAYLOAD);
    });

    /**
     * The reason this operation exists in the keyring rather than being
     * composed from unwrapInto + open on the main thread: the Item Key is
     * never stored, so a vault of a thousand secrets leaves one handle behind
     * rather than a thousand keys.
     */
    it('leaves no handle behind', () => {
        const { keyring, account } = openAccount();
        const stored = createVault(keyring, account.registration.x25519PublicKey);

        const fresh = reopenAccount(account);
        fresh.openSealedInto(VAULT_KEY, X25519_KEY, stored.wrappedVaultKey, membershipAad);

        const before = [...fresh.handles];
        fresh.openWithWrappedKey(bulkItem(stored));

        expect(fresh.handles).toEqual(before);
        expect(fresh.handles).not.toContain(ITEM_KEY);
    });

    it('still binds the payload to its own record', () => {
        const { keyring, account } = openAccount();
        const stored = createVault(keyring, account.registration.x25519PublicKey);

        expect(() =>
            keyring.openWithWrappedKey({
                ...bulkItem(stored),
                payloadAad: aad('vault.payload', OTHER_UUID),
            }),
        ).toThrow(IntegrityError);
    });

    it('still binds the item key to its own record', () => {
        const { keyring, account } = openAccount();
        const stored = createVault(keyring, account.registration.x25519PublicKey);

        expect(() =>
            keyring.openWithWrappedKey({ ...bulkItem(stored), keyAad: aad('item.key', OTHER_UUID) }),
        ).toThrow(IntegrityError);
    });

    it('refuses when the vault key is not held', () => {
        const { keyring, account } = openAccount();
        const stored = createVault(keyring, account.registration.x25519PublicKey);

        keyring.forget(VAULT_KEY);

        expect(() => keyring.openWithWrappedKey(bulkItem(stored))).toThrow(KeyUnavailableError);
    });
});

describe('locking', () => {
    it('drops vault and item keys along with everything else', () => {
        const { keyring, account } = openAccount();
        createVault(keyring, account.registration.x25519PublicKey);

        keyring.lock();

        expect(keyring.handles).toEqual([]);
    });
});
