import { describe, expect, it } from 'vitest';

import type { AadParams } from '../aad';
import { IntegrityError, KeyUnavailableError } from '../errors';
import { computeFingerprint, verifyPublicKeys } from '../identity';
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

describe('registration', () => {
    const UUID = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f6';

    const register = (keyring: Keyring, password = 'correct horse battery staple') =>
        keyring.register({ password, kdfSalt: generateKdfSalt(), kdfParams: FAST_KDF, uuid: UUID });

    it('produces every blob the server needs to store', () => {
        const result = register(new Keyring());

        expect(result.authKey).toHaveLength(32);
        expect(result.x25519PublicKey).toHaveLength(32);
        expect(result.ed25519PublicKey).toHaveLength(32);
        expect(result.selfSignature).toHaveLength(64);
        expect(result.fingerprint).toHaveLength(32);
        expect(result.recoverySalt).toHaveLength(16);
        expect(result.recoveryCode).toMatch(/^([0-9A-HJKMNP-TV-Z]{4}-){6}[0-9A-HJKMNP-TV-Z]{2}$/);
    });

    it('leaves the new account unlocked', () => {
        const keyring = new Keyring();
        register(keyring);

        expect(keyring.unlocked).toBe(true);
    });

    it('publishes a verifiable identity', () => {
        const result = register(new Keyring());

        expect(verifyPublicKeys(result.selfSignature, result.ed25519PublicKey, result.x25519PublicKey)).toBe(
            true,
        );
        expect(computeFingerprint(result.ed25519PublicKey, result.x25519PublicKey)).toEqual(
            result.fingerprint,
        );
    });

    it('encrypts the private keys so only the User Key opens them', () => {
        const keyring = new Keyring();
        const result = register(keyring);

        // Decryptable through the keyring, which holds the User Key...
        expect(
            keyring.open(USER_KEY, result.x25519PrivateKeyCt, {
                context: 'user.privkey.x25519',
                subject: UUID,
                version: 1,
            }),
        ).toHaveLength(32);

        // ...and bound to their own context, so they are not interchangeable.
        expect(() =>
            keyring.open(USER_KEY, result.x25519PrivateKeyCt, {
                context: 'user.privkey.ed25519',
                subject: UUID,
                version: 1,
            }),
        ).toThrow(IntegrityError);
    });

    it('is unlockable afterwards by password', () => {
        const keyring = new Keyring();
        const kdfSalt = generateKdfSalt();
        const result = keyring.register({
            password: 'correct horse',
            kdfSalt,
            kdfParams: FAST_KDF,
            uuid: UUID,
        });

        const fresh = new Keyring();
        fresh.unlock({
            password: 'correct horse',
            kdfSalt,
            kdfParams: FAST_KDF,
            wrappedUserKey: result.wrappedUserKey,
            userKeyAad: { context: 'user.userkey', subject: UUID, version: 1 },
        });

        expect(fresh.unlocked).toBe(true);
    });

    it('is unlockable afterwards by recovery code', () => {
        const result = register(new Keyring());

        const fresh = new Keyring();
        fresh.unlockWithRecovery(result.recoveryCode, result.recoverySalt, result.recoveryWrappedUserKey, {
            context: 'user.userkey',
            subject: UUID,
            version: 1,
        });

        expect(fresh.unlocked).toBe(true);
    });

    it('rejects the wrong recovery code', () => {
        const result = register(new Keyring());

        expect(() =>
            new Keyring().unlockWithRecovery(
                'ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZ',
                result.recoverySalt,
                result.recoveryWrappedUserKey,
                { context: 'user.userkey', subject: UUID, version: 1 },
            ),
        ).toThrow(IntegrityError);
    });

    it('discards any previous session', () => {
        const keyring = new Keyring();
        keyring.unlock(account());
        register(keyring);

        expect(keyring.handles).toEqual([USER_KEY]);
    });
});

describe('password change', () => {
    const UUID = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f6';
    const userKeyAad = { context: 'user.userkey', subject: UUID, version: 1 } as const;

    it('re-wraps the same User Key under a new password', () => {
        const keyring = new Keyring();
        const original = keyring.register({
            password: 'old password',
            kdfSalt: generateKdfSalt(),
            kdfParams: FAST_KDF,
            uuid: UUID,
        });

        const newSalt = generateKdfSalt();
        const rewrapped = keyring.rewrapForPassword('new password', newSalt, FAST_KDF, userKeyAad);

        const fresh = new Keyring();
        fresh.unlock({
            password: 'new password',
            kdfSalt: newSalt,
            kdfParams: FAST_KDF,
            wrappedUserKey: rewrapped.wrappedUserKey,
            userKeyAad,
        });

        expect(fresh.unlocked).toBe(true);

        // The identity ciphertexts were produced under the User Key, and the
        // User Key did not change — so they still open. This is the property
        // that makes a password change cheap.
        expect(
            fresh.open(USER_KEY, original.ed25519PrivateKeyCt, {
                context: 'user.privkey.ed25519',
                subject: UUID,
                version: 1,
            }),
        ).toHaveLength(32);
    });

    it('leaves the old password unable to unwrap the new wrapping', () => {
        const keyring = new Keyring();
        const kdfSalt = generateKdfSalt();
        keyring.register({ password: 'old password', kdfSalt, kdfParams: FAST_KDF, uuid: UUID });

        const rewrapped = keyring.rewrapForPassword('new password', generateKdfSalt(), FAST_KDF, userKeyAad);

        expect(() =>
            new Keyring().unlock({
                password: 'old password',
                kdfSalt,
                kdfParams: FAST_KDF,
                wrappedUserKey: rewrapped.wrappedUserKey,
                userKeyAad,
            }),
        ).toThrow(IntegrityError);
    });

    it('refuses to re-wrap while locked', () => {
        expect(() => new Keyring().rewrapForPassword('new', generateKdfSalt(), FAST_KDF, userKeyAad)).toThrow(
            KeyUnavailableError,
        );
    });
});

describe('recovery kit reissue', () => {
    const UUID = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f6';
    const userKeyAad = { context: 'user.userkey', subject: UUID, version: 1 } as const;

    it('issues a kit that opens the same User Key', () => {
        const keyring = new Keyring();
        keyring.register({
            password: 'correct horse',
            kdfSalt: generateKdfSalt(),
            kdfParams: FAST_KDF,
            uuid: UUID,
        });

        const kit = keyring.issueRecoveryKit(userKeyAad);

        const fresh = new Keyring();
        fresh.unlockWithRecovery(kit.recoveryCode, kit.recoverySalt, kit.recoveryWrappedUserKey, userKeyAad);

        expect(fresh.unlocked).toBe(true);
    });

    it('invalidates nothing on the server, but produces a different code each time', () => {
        const keyring = new Keyring();
        keyring.register({
            password: 'correct horse',
            kdfSalt: generateKdfSalt(),
            kdfParams: FAST_KDF,
            uuid: UUID,
        });

        const codes = new Set(
            Array.from({ length: 5 }, () => keyring.issueRecoveryKit(userKeyAad).recoveryCode),
        );

        expect(codes.size).toBe(5);
    });

    it('refuses to issue a kit while locked', () => {
        expect(() => new Keyring().issueRecoveryKit(userKeyAad)).toThrow(KeyUnavailableError);
    });
});
