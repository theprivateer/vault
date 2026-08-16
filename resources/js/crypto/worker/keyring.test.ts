import { describe, expect, it } from 'vitest';

import type { AadParams } from '../aad';
import { IntegrityError, KeyUnavailableError } from '../errors';
import { fingerprintHex } from '../grant';
import { computeFingerprint, verifyPublicKeys } from '../identity';
import { deriveFromPassword, generateKdfSalt, generateKey, openSealed, sealTo, wrapKey } from '../keys';
import { utf8ToBytes } from '../primitives';
import { verifyRotation } from '../rotation';
import type { RegistrationResult } from './keyring';
import { Keyring } from './keyring';
import { ED25519_KEY, USER_KEY, X25519_KEY } from './protocol';

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

/**
 * Identity rotation (Phase 10).
 *
 * The operation with the worst failure mode in the system: the old X25519
 * private key is discarded when a rotation lands, so a membership whose sealed
 * Vault Key was not re-sealed becomes a vault the user can never open again.
 * There is no error and nothing to recover from. That is why the server refuses
 * an incomplete set, and why the re-sealing here is checked by actually opening
 * the result rather than by measuring it.
 */
describe('identity rotation', () => {
    const UUID = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f6';
    const MEMBERSHIP = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5fa';
    const OTHER_MEMBERSHIP = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5fb';

    const membershipAad = (subject: string): AadParams => ({
        context: 'vault.membership.key',
        subject,
        version: 1,
    });

    const privateKeyAad = (context: 'user.privkey.x25519' | 'user.privkey.ed25519'): AadParams => ({
        context,
        subject: UUID,
        version: 1,
    });

    /** An account with its identity keys loaded, as unlock leaves it. */
    function registered(): { keyring: Keyring; identity: RegistrationResult } {
        const keyring = new Keyring();
        const identity = keyring.register({
            password: 'correct horse',
            kdfSalt: generateKdfSalt(),
            kdfParams: FAST_KDF,
            uuid: UUID,
        });

        keyring.unwrapInto(
            X25519_KEY,
            USER_KEY,
            identity.x25519PrivateKeyCt,
            privateKeyAad('user.privkey.x25519'),
        );
        keyring.unwrapInto(
            ED25519_KEY,
            USER_KEY,
            identity.ed25519PrivateKeyCt,
            privateKeyAad('user.privkey.ed25519'),
        );

        return { keyring, identity };
    }

    function rotate(keyring: Keyring, memberships: { uuid: string; sealed: Uint8Array }[] = []) {
        return keyring.rotateIdentity({ uuid: UUID, rotatedAt: '2026-08-16T09:00:00Z', memberships });
    }

    it('publishes a fresh, self-consistent identity', () => {
        const result = rotate(registered().keyring);

        expect(verifyPublicKeys(result.selfSignature, result.ed25519PublicKey, result.x25519PublicKey)).toBe(
            true,
        );
        expect(computeFingerprint(result.ed25519PublicKey, result.x25519PublicKey)).toEqual(
            result.fingerprint,
        );
    });

    it('replaces the keys rather than republishing them', () => {
        const { keyring, identity } = registered();
        const result = rotate(keyring);

        expect(result.x25519PublicKey).not.toEqual(identity.x25519PublicKey);
        expect(result.ed25519PublicKey).not.toEqual(identity.ed25519PublicKey);
        expect(result.fingerprint).not.toEqual(identity.fingerprint);
    });

    /*
     | The heart of it, and the reason rotation is self-service: the user still
     | holds their *old* private key, so their own browser can move every sealed
     | Vault Key across. No vault owner is involved and no Vault Key changes.
     |
     | Checked by opening the re-sealed value with the new private key and
     | comparing the bytes, because a length assertion would pass just as
     | happily on a re-seal of something else entirely.
     */
    it('moves each vault key to the new identity, byte for byte', () => {
        const { keyring, identity } = registered();
        const vaultKey = generateKey();

        const sealed = sealTo(identity.x25519PublicKey, vaultKey, membershipAad(MEMBERSHIP));
        const result = rotate(keyring, [{ uuid: MEMBERSHIP, sealed }]);

        expect(result.memberships).toHaveLength(1);
        expect(result.memberships[0]!.uuid).toBe(MEMBERSHIP);

        expect(
            openSealed(
                keyring.open(USER_KEY, result.x25519PrivateKeyCt, privateKeyAad('user.privkey.x25519')),
                result.memberships[0]!.wrappedVaultKey,
                membershipAad(MEMBERSHIP),
            ),
        ).toEqual(vaultKey);
    });

    /*
     | The associated data is the membership's own UUID and does not change
     | across a rotation — the row is the same row. Re-sealing under a different
     | subject would make a rotation a way to move somebody's key onto another
     | membership, which is exactly what the AAD binding exists to prevent (SR4).
     */
    it('keeps each key bound to its own membership', () => {
        const { keyring, identity } = registered();
        const vaultKey = generateKey();

        const sealed = sealTo(identity.x25519PublicKey, vaultKey, membershipAad(MEMBERSHIP));
        const result = rotate(keyring, [{ uuid: MEMBERSHIP, sealed }]);

        const newPrivateKey = keyring.open(
            USER_KEY,
            result.x25519PrivateKeyCt,
            privateKeyAad('user.privkey.x25519'),
        );

        expect(() =>
            openSealed(
                newPrivateKey,
                result.memberships[0]!.wrappedVaultKey,
                membershipAad(OTHER_MEMBERSHIP),
            ),
        ).toThrow(IntegrityError);
    });

    it('carries every membership it was given, in order', () => {
        const { keyring, identity } = registered();

        const memberships = [MEMBERSHIP, OTHER_MEMBERSHIP].map((uuid) => ({
            uuid,
            sealed: sealTo(identity.x25519PublicKey, generateKey(), membershipAad(uuid)),
        }));

        expect(rotate(keyring, memberships).memberships.map((entry) => entry.uuid)).toEqual([
            MEMBERSHIP,
            OTHER_MEMBERSHIP,
        ]);
    });

    /*
     | Signed by the key being retired, which is the whole value of the
     | certificate: a peer holding the old fingerprint can tell "they rotated"
     | from "the server substituted a key". A certificate signed by the new key
     | would attest only that the new key exists.
     */
    it('certifies the new keys with the retired Ed25519 key', () => {
        const { keyring, identity } = registered();
        const result = rotate(keyring);

        expect(
            verifyRotation(
                result.certificate.signature,
                result.certificate.payload,
                identity.ed25519PublicKey,
                {
                    userUuid: UUID,
                    previousFingerprint: fingerprintHex(identity.fingerprint),
                    fingerprint: fingerprintHex(result.fingerprint),
                },
            ).certified,
        ).toBe(true);
    });

    /*
     | The keyring still holds the *old* keys afterwards, deliberately. The
     | server may refuse the submission, and a Worker holding keys the server has
     | never seen could not open a single membership — the user would be locked
     | out of everything by an operation that failed.
     */
    it('leaves the held keys alone until the write has landed', () => {
        const { keyring, identity } = registered();
        const vaultKey = generateKey();
        const sealed = sealTo(identity.x25519PublicKey, vaultKey, membershipAad(MEMBERSHIP));

        rotate(keyring, [{ uuid: MEMBERSHIP, sealed }]);

        // The old sealed key still opens with the still-held old private key.
        keyring.openSealedInto('vault:test', X25519_KEY, sealed, membershipAad(MEMBERSHIP));

        expect(keyring.handles).toContain('vault:test');
    });

    it('refuses to rotate a locked keyring', () => {
        expect(() => rotate(new Keyring())).toThrow(KeyUnavailableError);
    });

    /*
     | An unlocked account whose identity keys were never loaded cannot rotate:
     | it has nothing to open the old sealed keys with, and nothing to sign the
     | certificate. Failing here is right — the alternative is a rotation that
     | strands every membership it could not read.
     */
    it('refuses when the identity keys are not loaded', () => {
        const keyring = new Keyring();
        keyring.register({
            password: 'correct horse',
            kdfSalt: generateKdfSalt(),
            kdfParams: FAST_KDF,
            uuid: UUID,
        });

        expect(() => rotate(keyring)).toThrow(KeyUnavailableError);
    });
});
