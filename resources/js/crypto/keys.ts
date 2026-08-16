/**
 * The key hierarchy.
 *
 *   password ──Argon2id──> 64 bytes
 *                            ├─ [0..32]  KEK      (never leaves the device)
 *                            └─ [32..64] authKey  (all the server ever sees)
 *
 *   KEK           ──unwraps──> User Key ──unwraps──> X25519 / Ed25519 private keys
 *   RecoveryKEK   ──unwraps──> User Key
 *   Vault Key     ──wraps────> Item Keys ──encrypt──> payloads
 *
 * Spec: docs/03-cryptographic-design.md
 */
import { ed25519, x25519 } from '@noble/curves/ed25519.js';

import type { AadParams } from './aad';
import { decodeBase32, encodeBase32, group } from './encoding';
import { open, seal } from './envelope';
import { InvalidParameterError, MalformedEnvelopeError } from './errors';
import type { KdfParams } from './primitives';
import {
    DEFAULT_KDF_PARAMS,
    KEY_LENGTH,
    concat,
    deriveKey,
    randomBytes,
    stretchPassword,
    zeroise,
} from './primitives';

const PUBLIC_KEY_LENGTH = 32;

/** 128 bits of uniform randomness, rendered as 26 base32 characters. */
const RECOVERY_CODE_BYTES = 16;

export interface StretchedPassword {
    /** Key-encryption key. Stays in the browser, always. */
    kek: Uint8Array;
    /** Sent to the server on login. The server stores only a slow hash of it. */
    authKey: Uint8Array;
}

/**
 * Splits one password into two independent keys.
 *
 * The server never receives the password or the KEK. It receives `authKey`,
 * which is useless for decryption — but note that it inherits only the
 * password's entropy, not 256 bits, so the server must still store it under a
 * slow hash.
 */
export function deriveFromPassword(
    password: string,
    salt: Uint8Array,
    params: KdfParams = DEFAULT_KDF_PARAMS,
): StretchedPassword {
    const stretched = stretchPassword(password, salt, params);

    const result = {
        kek: stretched.slice(0, KEY_LENGTH),
        authKey: stretched.slice(KEY_LENGTH),
    };

    zeroise(stretched);

    return result;
}

/** A fresh symmetric key: a User Key, a Vault Key, or an Item Key. */
export function generateKey(): Uint8Array {
    return randomBytes(KEY_LENGTH);
}

export function generateKdfSalt(): Uint8Array {
    return randomBytes(16);
}

/**
 * Wraps a key under another key. A thin alias over `seal`, named for what it
 * does so call sites read as key management rather than encryption.
 */
export function wrapKey(wrappingKey: Uint8Array, key: Uint8Array, aad: AadParams): Uint8Array {
    if (key.length !== KEY_LENGTH) {
        throw new InvalidParameterError(`Can only wrap a ${KEY_LENGTH} byte key, received ${key.length}.`);
    }

    return seal(wrappingKey, key, aad);
}

export function unwrapKey(wrappingKey: Uint8Array, wrapped: Uint8Array, aad: AadParams): Uint8Array {
    const key = open(wrappingKey, wrapped, aad);

    if (key.length !== KEY_LENGTH) {
        // The tag verified, so this is not tampering — it is a wrapped value
        // that was never a key. Failing loudly beats returning something the
        // caller will use as one.
        throw new MalformedEnvelopeError(
            `Unwrapped value is ${key.length} bytes, expected a ${KEY_LENGTH} byte key.`,
        );
    }

    return key;
}

export interface RecoveryKeys {
    /** Wraps a second copy of the User Key. Never leaves the device. */
    kek: Uint8Array;
    /**
     * Proves possession of the recovery code to the server, which stores only a
     * hash of it.
     *
     * The same split as the password (D4), and for the same reason: the server
     * must be able to verify a recovery attempt without learning anything that
     * unwraps the User Key. Sending the code itself would hand a server that
     * already holds the wrapped key everything it needs.
     */
    authKey: Uint8Array;
}

export interface RecoveryCode extends RecoveryKeys {
    /** Grouped for printing: XXXX-XXXX-XXXX-… */
    formatted: string;
    salt: Uint8Array;
}

/**
 * Generates the recovery kit shown once at signup.
 *
 * HKDF rather than Argon2id, deliberately: the input is already 128 bits of
 * uniform randomness, so a slow KDF would cost the user time and buy nothing.
 * The password gets Argon2id because it is low entropy. That distinction is the
 * point, not an inconsistency.
 */
export function generateRecoveryCode(): RecoveryCode {
    const code = randomBytes(RECOVERY_CODE_BYTES);
    const salt = randomBytes(16);
    const formatted = group(encodeBase32(code));

    zeroise(code);

    return { formatted, salt, ...deriveRecoveryKeys(formatted, salt) };
}

/**
 * Re-derives both recovery keys from a code the user has typed back in.
 *
 * HKDF rather than Argon2id: the input is already 128 bits of uniform
 * randomness, so a slow KDF would cost the user time and buy nothing. The
 * password gets Argon2id because it is low entropy. That distinction is the
 * point, not an inconsistency.
 */
export function deriveRecoveryKeys(formattedCode: string, salt: Uint8Array): RecoveryKeys {
    const code = decodeBase32(formattedCode);

    if (code.length !== RECOVERY_CODE_BYTES) {
        throw new InvalidParameterError(
            `Recovery code decodes to ${code.length} bytes, expected ${RECOVERY_CODE_BYTES}.`,
        );
    }

    const keys = {
        kek: deriveKey(code, salt, 'vault:recovery:enc:v1'),
        authKey: deriveKey(code, salt, 'vault:recovery:auth:v1'),
    };

    zeroise(code);

    return keys;
}

export interface KeyPair {
    publicKey: Uint8Array;
    secretKey: Uint8Array;
}

/**
 * The public half of a held X25519 private key.
 *
 * Needed because the keyring stores private keys and nothing else: a rotation
 * has to name the fingerprint it is retiring, and a fingerprint is computed from
 * public keys. Re-deriving is the honest way to get them — the alternative is
 * carrying the public halves alongside, where they could drift out of step with
 * the private ones and produce a certificate that retires a key nobody held.
 */
export function x25519PublicKeyOf(secretKey: Uint8Array): Uint8Array {
    return x25519.getPublicKey(secretKey);
}

export function ed25519PublicKeyOf(secretKey: Uint8Array): Uint8Array {
    return ed25519.getPublicKey(secretKey);
}

export function generateX25519KeyPair(): KeyPair {
    const secretKey = x25519.utils.randomSecretKey();

    return { secretKey, publicKey: x25519.getPublicKey(secretKey) };
}

/**
 * Seals a payload to a recipient's X25519 public key.
 *
 * An ephemeral keypair per seal gives forward secrecy against later compromise
 * of the sender's key, and makes the output anonymous — which is why a grant
 * carries a separate Ed25519 signature to establish who sent it.
 *
 *   output = ephemeralPublicKey ‖ envelope
 */
export function sealTo(recipientPublicKey: Uint8Array, plaintext: Uint8Array, aad: AadParams): Uint8Array {
    assertPublicKey(recipientPublicKey);

    const ephemeralSecret = x25519.utils.randomSecretKey();
    const ephemeralPublic = x25519.getPublicKey(ephemeralSecret);

    const shared = x25519.getSharedSecret(ephemeralSecret, recipientPublicKey);
    const key = deriveSealKey(shared, ephemeralPublic, recipientPublicKey);

    const sealed = concat(ephemeralPublic, seal(key, plaintext, aad));

    zeroise(ephemeralSecret, shared, key);

    return sealed;
}

export function openSealed(recipientSecretKey: Uint8Array, sealed: Uint8Array, aad: AadParams): Uint8Array {
    if (sealed.length <= PUBLIC_KEY_LENGTH) {
        throw new MalformedEnvelopeError(
            `Sealed box is ${sealed.length} bytes, too short to contain an ephemeral public key.`,
        );
    }

    const ephemeralPublic = sealed.subarray(0, PUBLIC_KEY_LENGTH);
    const envelope = sealed.subarray(PUBLIC_KEY_LENGTH);

    const recipientPublic = x25519.getPublicKey(recipientSecretKey);
    const shared = x25519.getSharedSecret(recipientSecretKey, ephemeralPublic);
    const key = deriveSealKey(shared, ephemeralPublic, recipientPublic);

    try {
        return open(key, envelope, aad);
    } finally {
        zeroise(shared, key);
    }
}

/**
 * Binds the derived key to both public keys, not just the shared secret, so a
 * key derived for one recipient cannot be replayed against another.
 */
function deriveSealKey(
    shared: Uint8Array,
    ephemeralPublic: Uint8Array,
    recipientPublic: Uint8Array,
): Uint8Array {
    return deriveKey(concat(shared, ephemeralPublic, recipientPublic), undefined, 'vault:seal:v1');
}

function assertPublicKey(key: Uint8Array): void {
    if (key.length !== PUBLIC_KEY_LENGTH) {
        throw new InvalidParameterError(
            `Public key must be ${PUBLIC_KEY_LENGTH} bytes, received ${key.length}.`,
        );
    }
}
