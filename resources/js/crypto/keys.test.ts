import { describe, expect, it } from 'vitest';

import type { AadParams } from './aad';
import { seal } from './envelope';
import { IntegrityError, InvalidParameterError, MalformedEnvelopeError } from './errors';
import {
    deriveFromPassword,
    deriveRecoveryKeys,
    generateKdfSalt,
    generateKey,
    generateRecoveryCode,
    generateX25519KeyPair,
    openSealed,
    sealTo,
    unwrapKey,
    wrapKey,
} from './keys';
import { KEY_LENGTH, utf8ToBytes } from './primitives';

/**
 * Argon2id at production parameters costs ~731 ms per call (ADR-0003), which
 * would make this suite unusable. These tests verify wiring, not cost — the
 * real parameters are exercised by `npm run bench:argon2`.
 */
const FAST_KDF = { m: 8, t: 1, p: 1 };

const SUBJECT = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f6';
const aad: AadParams = { context: 'user.userkey', subject: SUBJECT, version: 1 };

describe('deriveFromPassword', () => {
    const salt = generateKdfSalt();

    it('produces two independent 32 byte keys', () => {
        const { kek, authKey } = deriveFromPassword('correct horse', salt, FAST_KDF);

        expect(kek).toHaveLength(KEY_LENGTH);
        expect(authKey).toHaveLength(KEY_LENGTH);

        // The whole scheme rests on these being different: the server receives
        // authKey, and must learn nothing about kek from it.
        expect(kek).not.toEqual(authKey);
    });

    it('is deterministic for the same password and salt', () => {
        const a = deriveFromPassword('correct horse', salt, FAST_KDF);
        const b = deriveFromPassword('correct horse', salt, FAST_KDF);

        expect(a.kek).toEqual(b.kek);
        expect(a.authKey).toEqual(b.authKey);
    });

    it('diverges completely on a different salt', () => {
        const a = deriveFromPassword('correct horse', salt, FAST_KDF);
        const b = deriveFromPassword('correct horse', generateKdfSalt(), FAST_KDF);

        expect(a.kek).not.toEqual(b.kek);
        expect(a.authKey).not.toEqual(b.authKey);
    });

    it('diverges on a one character password change', () => {
        const a = deriveFromPassword('correct horse', salt, FAST_KDF);
        const b = deriveFromPassword('correct horsf', salt, FAST_KDF);

        expect(a.kek).not.toEqual(b.kek);
    });

    it('diverges on different parameters', () => {
        const a = deriveFromPassword('correct horse', salt, FAST_KDF);
        const b = deriveFromPassword('correct horse', salt, { ...FAST_KDF, t: 2 });

        expect(a.kek).not.toEqual(b.kek);
    });

    it('refuses an empty password', () => {
        expect(() => deriveFromPassword('', salt, FAST_KDF)).toThrow(InvalidParameterError);
    });

    it('refuses a salt shorter than 16 bytes', () => {
        expect(() => deriveFromPassword('correct horse', new Uint8Array(15), FAST_KDF)).toThrow(
            InvalidParameterError,
        );
    });
});

describe('key wrapping', () => {
    it('round trips', () => {
        const wrappingKey = generateKey();
        const key = generateKey();

        expect(unwrapKey(wrappingKey, wrapKey(wrappingKey, key, aad), aad)).toEqual(key);
    });

    it('refuses to wrap something that is not a key', () => {
        expect(() => wrapKey(generateKey(), new Uint8Array(16), aad)).toThrow(InvalidParameterError);
    });

    it('refuses to unwrap a value that is not key shaped', () => {
        const wrappingKey = generateKey();
        // Sealed directly, bypassing wrapKey's length check. The tag verifies,
        // so this is not tampering — it is a wrapped value that was never a key.
        // Better to fail than hand back something the caller will use as one.
        const notAKey = seal(wrappingKey, utf8ToBytes('not thirty two bytes'), aad);

        expect(() => unwrapKey(wrappingKey, notAKey, aad)).toThrow(MalformedEnvelopeError);
    });

    it('refuses a wrapped key rebound to a different record', () => {
        const wrappingKey = generateKey();
        const wrapped = wrapKey(wrappingKey, generateKey(), aad);

        expect(() =>
            unwrapKey(wrappingKey, wrapped, { ...aad, subject: '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f7' }),
        ).toThrow(IntegrityError);
    });
});

describe('recovery codes', () => {
    it('produces a grouped code that derives a key', () => {
        const { formatted, kek, salt } = generateRecoveryCode();

        // 128 bits encodes to 26 base32 characters: six groups of four, then two.
        expect(formatted).toMatch(/^([0-9A-HJKMNP-TV-Z]{4}-){6}[0-9A-HJKMNP-TV-Z]{2}$/);
        expect(kek).toHaveLength(KEY_LENGTH);
        expect(deriveRecoveryKeys(formatted, salt).kek).toEqual(kek);
    });

    it('is different every time', () => {
        const codes = Array.from({ length: 20 }, () => generateRecoveryCode().formatted);

        expect(new Set(codes).size).toBe(20);
    });

    it.each([
        ['lower case', (code: string) => code.toLowerCase()],
        ['without separators', (code: string) => code.replace(/-/g, '')],
        ['with spaces instead of dashes', (code: string) => code.replace(/-/g, ' ')],
    ])('accepts the code typed back %s', (_label, transform) => {
        const { formatted, kek, salt } = generateRecoveryCode();

        expect(deriveRecoveryKeys(transform(formatted), salt).kek).toEqual(kek);
    });

    it('folds the ambiguous characters a human would mistype', () => {
        // Crockford omits I, L and O precisely because they are misread as 1 and 0.
        const { salt } = generateRecoveryCode();

        expect(deriveRecoveryKeys('OIOI-OIOI-OIOI-OIOI-OIOI-OIOI-OI', salt)).toEqual(
            deriveRecoveryKeys('0101-0101-0101-0101-0101-0101-01', salt),
        );
    });

    it('rejects U rather than guessing, since it is not in the alphabet', () => {
        const { salt } = generateRecoveryCode();

        // Folding U to something else would silently corrupt the code and
        // present as an unexplained failure to unlock.
        expect(() => deriveRecoveryKeys('UUUU-UUUU-UUUU-UUUU-UUUU-UUUU-UU', salt)).toThrow(
            InvalidParameterError,
        );
    });

    it('rejects a code of the wrong length', () => {
        const { salt } = generateRecoveryCode();

        expect(() => deriveRecoveryKeys('ABCD-EFGH', salt)).toThrow(InvalidParameterError);
    });

    it('rejects a code containing an invalid character', () => {
        const { salt } = generateRecoveryCode();

        expect(() => deriveRecoveryKeys('ABCD-EFGH-JKMN-PQRS-TVWX-YZAB-C!', salt)).toThrow(
            InvalidParameterError,
        );
    });
});

describe('sealed boxes', () => {
    const sealAad: AadParams = { context: 'vault.membership.key', subject: SUBJECT, version: 1 };

    it('round trips to the intended recipient', () => {
        const recipient = generateX25519KeyPair();
        const vaultKey = generateKey();

        const sealed = sealTo(recipient.publicKey, vaultKey, sealAad);

        expect(openSealed(recipient.secretKey, sealed, sealAad)).toEqual(vaultKey);
    });

    it('cannot be opened by anyone else', () => {
        const recipient = generateX25519KeyPair();
        const eavesdropper = generateX25519KeyPair();

        const sealed = sealTo(recipient.publicKey, generateKey(), sealAad);

        expect(() => openSealed(eavesdropper.secretKey, sealed, sealAad)).toThrow(IntegrityError);
    });

    it('is non-deterministic, so identical grants differ', () => {
        const recipient = generateX25519KeyPair();
        const vaultKey = generateKey();

        const sealed = Array.from({ length: 10 }, () =>
            sealTo(recipient.publicKey, vaultKey, sealAad).toString(),
        );

        expect(new Set(sealed).size).toBe(10);
    });

    it('carries the ephemeral public key ahead of the envelope', () => {
        const recipient = generateX25519KeyPair();
        const sealed = sealTo(recipient.publicKey, generateKey(), sealAad);

        // 32 byte ephemeral key + 2 header + 24 nonce + 32 payload + 16 tag
        expect(sealed).toHaveLength(32 + 2 + 24 + 32 + 16);
    });

    it('rejects a substituted ephemeral public key', () => {
        const recipient = generateX25519KeyPair();
        const sealed = sealTo(recipient.publicKey, generateKey(), sealAad);

        sealed.set(generateX25519KeyPair().publicKey, 0);

        expect(() => openSealed(recipient.secretKey, sealed, sealAad)).toThrow(IntegrityError);
    });

    it('rejects a sealed box rebound to a different membership', () => {
        const recipient = generateX25519KeyPair();
        const sealed = sealTo(recipient.publicKey, generateKey(), sealAad);

        expect(() =>
            openSealed(recipient.secretKey, sealed, {
                ...sealAad,
                subject: '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f7',
            }),
        ).toThrow(IntegrityError);
    });

    it('rejects a truncated sealed box', () => {
        expect(() => openSealed(generateX25519KeyPair().secretKey, new Uint8Array(32), sealAad)).toThrow(
            MalformedEnvelopeError,
        );
    });

    it('refuses a recipient key of the wrong length', () => {
        expect(() => sealTo(new Uint8Array(31), generateKey(), sealAad)).toThrow(InvalidParameterError);
    });
});

describe('recovery key separation', () => {
    /*
     | The same split as the password (D4): the server must be able to verify a
     | recovery attempt without learning anything that unwraps the User Key.
     | If these two were equal, handing the auth key to the server would hand it
     | the KEK — and the server already holds the wrapped key.
     */
    it('derives an encryption key and an auth key that are independent', () => {
        const { formatted, salt, kek, authKey } = generateRecoveryCode();

        expect(kek).toHaveLength(KEY_LENGTH);
        expect(authKey).toHaveLength(KEY_LENGTH);
        expect(kek).not.toEqual(authKey);

        const rederived = deriveRecoveryKeys(formatted, salt);

        expect(rederived.kek).toEqual(kek);
        expect(rederived.authKey).toEqual(authKey);
    });

    it('separates the two by salt as well as by info', () => {
        const { formatted } = generateRecoveryCode();

        const first = deriveRecoveryKeys(formatted, generateKdfSalt());
        const second = deriveRecoveryKeys(formatted, generateKdfSalt());

        expect(first.kek).not.toEqual(second.kek);
        expect(first.authKey).not.toEqual(second.authKey);
    });
});
