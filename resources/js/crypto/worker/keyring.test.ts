import { describe, expect, it } from 'vitest';

import type { AadParams } from '../aad';
import { IntegrityError, KeyUnavailableError } from '../errors';
import { deriveFromPassword, generateKdfSalt, generateKey, wrapKey } from '../keys';
import { utf8ToBytes } from '../primitives';
import { Keyring } from './keyring';
import { USER_KEY } from './protocol';

const FAST_KDF = { m: 8, t: 1, p: 1 };

const SUBJECT = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f6';
const VAULT_SUBJECT = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f7';

const userKeyAad: AadParams = { context: 'user.userkey', subject: SUBJECT, version: 1 };
const itemAad: AadParams = { context: 'secret.payload', subject: SUBJECT, version: 1 };
const vaultKeyAad: AadParams = { context: 'item.key', subject: VAULT_SUBJECT, version: 1 };

interface Account {
    password: string;
    kdfSalt: Uint8Array;
    kdfParams: typeof FAST_KDF;
    wrappedUserKey: Uint8Array;
    userKeyAad: AadParams;
    userKey: Uint8Array;
}

function account(password = 'correct horse battery staple'): Account {
    const kdfSalt = generateKdfSalt();
    const userKey = generateKey();

    // Mirrors registration: derive the KEK, wrap the User Key under it.
    const { kek } = deriveFromPassword(password, kdfSalt, FAST_KDF);

    return {
        password,
        kdfSalt,
        kdfParams: FAST_KDF,
        userKeyAad,
        userKey,
        wrappedUserKey: wrapKey(kek, userKey, userKeyAad),
    };
}

describe('locking', () => {
    it('starts locked', () => {
        const keyring = new Keyring();

        expect(keyring.unlocked).toBe(false);
        expect(keyring.handles).toEqual([]);
    });

    it('unlocks with the correct password', () => {
        const keyring = new Keyring();
        keyring.unlock(account());

        expect(keyring.unlocked).toBe(true);
        expect(keyring.handles).toEqual([USER_KEY]);
    });

    it('refuses the wrong password', () => {
        const keyring = new Keyring();

        expect(() => keyring.unlock({ ...account(), password: 'wrong' })).toThrow(IntegrityError);
        expect(keyring.unlocked).toBe(false);
    });

    it('forgets everything on lock', () => {
        const keyring = new Keyring();
        const details = account();

        keyring.unlock(details);
        keyring.unwrapInto(
            'vault',
            USER_KEY,
            wrapKey(details.userKey, generateKey(), vaultKeyAad),
            vaultKeyAad,
        );

        expect(keyring.handles).toHaveLength(2);

        keyring.lock();

        expect(keyring.unlocked).toBe(false);
        expect(keyring.handles).toEqual([]);
    });

    it('discards a previous session when unlocking again', () => {
        const keyring = new Keyring();
        const details = account();

        keyring.unlock(details);
        keyring.unwrapInto(
            'vault',
            USER_KEY,
            wrapKey(details.userKey, generateKey(), vaultKeyAad),
            vaultKeyAad,
        );
        keyring.unlock(details);

        // The stale vault key must not survive a re-unlock.
        expect(keyring.handles).toEqual([USER_KEY]);
    });

    it('locking twice is harmless', () => {
        const keyring = new Keyring();
        keyring.unlock(account());
        keyring.lock();

        expect(() => keyring.lock()).not.toThrow();
    });
});

describe('operations', () => {
    it('seals and opens under a held key', () => {
        const keyring = new Keyring();
        keyring.unlock(account());

        const plaintext = utf8ToBytes('{"key":"prod db","value":"hunter2"}');
        const envelope = keyring.seal(USER_KEY, plaintext, itemAad);

        expect(keyring.open(USER_KEY, envelope, itemAad)).toEqual(plaintext);
    });

    it('walks the hierarchy without surfacing a key', () => {
        const keyring = new Keyring();
        const details = account();
        keyring.unlock(details);

        const vaultKey = generateKey();
        keyring.unwrapInto('vault', USER_KEY, wrapKey(details.userKey, vaultKey, vaultKeyAad), vaultKeyAad);

        const plaintext = utf8ToBytes('a vault payload');
        const envelope = keyring.seal('vault', plaintext, itemAad);

        expect(keyring.open('vault', envelope, itemAad)).toEqual(plaintext);
        expect(keyring.handles).toEqual(['vault', USER_KEY].sort());
    });

    it('refuses to operate on a handle it does not hold', () => {
        const keyring = new Keyring();
        keyring.unlock(account());

        expect(() => keyring.seal('missing', utf8ToBytes('x'), itemAad)).toThrow(KeyUnavailableError);
        expect(() => keyring.open('missing', new Uint8Array(42), itemAad)).toThrow(KeyUnavailableError);
        expect(() => keyring.unwrapInto('a', 'missing', new Uint8Array(74), itemAad)).toThrow(
            KeyUnavailableError,
        );
    });

    it('refuses every operation once locked', () => {
        const keyring = new Keyring();
        keyring.unlock(account());
        keyring.lock();

        expect(() => keyring.seal(USER_KEY, utf8ToBytes('x'), itemAad)).toThrow(KeyUnavailableError);
    });

    it('forgets a single handle', () => {
        const keyring = new Keyring();
        const details = account();
        keyring.unlock(details);
        keyring.unwrapInto(
            'vault',
            USER_KEY,
            wrapKey(details.userKey, generateKey(), vaultKeyAad),
            vaultKeyAad,
        );

        keyring.forget('vault');

        expect(keyring.handles).toEqual([USER_KEY]);
        expect(keyring.unlocked).toBe(true);
    });

    it('forgetting an unheld handle is harmless', () => {
        expect(() => new Keyring().forget('nothing')).not.toThrow();
    });

    it('replaces a handle rather than accumulating', () => {
        const keyring = new Keyring();
        const details = account();
        keyring.unlock(details);

        keyring.unwrapInto(
            'vault',
            USER_KEY,
            wrapKey(details.userKey, generateKey(), vaultKeyAad),
            vaultKeyAad,
        );
        keyring.unwrapInto(
            'vault',
            USER_KEY,
            wrapKey(details.userKey, generateKey(), vaultKeyAad),
            vaultKeyAad,
        );

        expect(keyring.handles).toEqual(['vault', USER_KEY].sort());
    });
});
