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
import { IntegrityError, InvalidParameterError, MalformedEnvelopeError } from '../errors';
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

    keyring.unwrapInto(X25519_KEY, USER_KEY, registration.x25519PrivateKeyCt, x25519Aad);

    return { keyring, account: { password, kdfSalt, registration } };
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

    keyring.unwrapInto(X25519_KEY, USER_KEY, account.registration.x25519PrivateKeyCt, x25519Aad);

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

        expect(keyring.handles).toEqual([X25519_KEY, ITEM_KEY, USER_KEY, VAULT_KEY].sort());
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

describe('locking', () => {
    it('drops vault and item keys along with everything else', () => {
        const { keyring, account } = openAccount();
        createVault(keyring, account.registration.x25519PublicKey);

        keyring.lock();

        expect(keyring.handles).toEqual([]);
    });
});
