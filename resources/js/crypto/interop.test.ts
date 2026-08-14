/**
 * Verifies the TypeScript crypto core against vectors produced independently by
 * PHP's ext-sodium.
 *
 * A round-trip test proves only that our encrypt and decrypt agree with each
 * other — they would agree just as happily while both being wrong about byte
 * order, parameter mapping or associated-data encoding. libsodium is the
 * independent implementation that catches that.
 *
 * The fixture is generated and re-verified by tests/Feature/CryptoInteropTest.php.
 * Regenerate with:
 *
 *   VAULT_UPDATE_CRYPTO_FIXTURE=1 php artisan test --filter=interop
 */
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { argon2id } from '@noble/hashes/argon2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { describe, expect, it } from 'vitest';

import vectors from '../../../tests/Fixtures/crypto-interop.json';
import type { AadContext } from './aad';
import { buildAad } from './aad';
import { deriveKey, hash256, stretchPassword, utf8ToBytes } from './primitives';

describe('associated data', () => {
    /*
     | The most valuable vector here. AAD is the binding that stops a malicious
     | server relocating ciphertexts between records (SR4), and its encoding is
     | hand-rolled rather than provided by a library — so it is exactly the sort
     | of thing two implementations could disagree about silently.
     */
    it('encodes identically to the independent PHP implementation', () => {
        const { params, bytes } = vectors.aad;

        expect(
            bytesToHex(
                buildAad({
                    context: params.context as AadContext,
                    subject: params.subject,
                    version: params.version,
                }),
            ),
        ).toBe(bytes);
    });
});

describe('XChaCha20-Poly1305', () => {
    const { key, nonce, aad, plaintext, body } = vectors.xchacha20poly1305;

    it('produces the ciphertext and tag libsodium produces', () => {
        const encrypted = xchacha20poly1305(hexToBytes(key), hexToBytes(nonce), hexToBytes(aad)).encrypt(
            hexToBytes(plaintext),
        );

        expect(bytesToHex(encrypted)).toBe(body);
    });

    it('decrypts what libsodium encrypted', () => {
        const decrypted = xchacha20poly1305(hexToBytes(key), hexToBytes(nonce), hexToBytes(aad)).decrypt(
            hexToBytes(body),
        );

        expect(bytesToHex(decrypted)).toBe(plaintext);
    });

    it('rejects libsodium ciphertext bound to a different record', () => {
        const rebound = buildAad({
            context: 'secret.payload',
            subject: '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f7',
            version: 1,
        });

        expect(() =>
            xchacha20poly1305(hexToBytes(key), hexToBytes(nonce), rebound).decrypt(hexToBytes(body)),
        ).toThrow();
    });
});

describe('BLAKE2b-256', () => {
    it('matches sodium_crypto_generichash', () => {
        expect(bytesToHex(hash256(hexToBytes(vectors.blake2b256.input)))).toBe(vectors.blake2b256.digest);
    });
});

describe('HKDF-SHA256', () => {
    it('matches hash_hkdf', () => {
        const { ikm, salt, info, okm } = vectors.hkdf_sha256;

        expect(bytesToHex(deriveKey(hexToBytes(ikm), hexToBytes(salt), info))).toBe(okm);
    });
});

describe('Argon2id', () => {
    /*
     | The parameter mapping is the risk: libsodium takes memlimit in bytes and
     | opslimit as a count, noble takes m in KiB and t as passes. Getting that
     | wrong would silently weaken the KDF while every round-trip test kept
     | passing.
     */
    it('matches sodium_crypto_pwhash with the equivalent parameters', () => {
        const { password, salt, m, t, p, dkLen, output } = vectors.argon2id;

        const derived = argon2id(password, hexToBytes(salt), { m, t, p, dkLen });

        expect(bytesToHex(derived)).toBe(output);
    });

    it('agrees through our own wrapper', () => {
        const { password, salt, m, t, p, output } = vectors.argon2id;

        // stretchPassword fixes dkLen at 64, which is what the fixture uses.
        expect(bytesToHex(stretchPassword(password, hexToBytes(salt), { m, t, p }))).toBe(output);
    });
});

describe('X25519', () => {
    const { aliceSecret, alicePublic, bobSecret, bobPublic, shared } = vectors.x25519;

    it('derives the same public keys', () => {
        expect(bytesToHex(x25519.getPublicKey(hexToBytes(aliceSecret)))).toBe(alicePublic);
        expect(bytesToHex(x25519.getPublicKey(hexToBytes(bobSecret)))).toBe(bobPublic);
    });

    it('agrees on the shared secret', () => {
        expect(bytesToHex(x25519.getSharedSecret(hexToBytes(aliceSecret), hexToBytes(bobPublic)))).toBe(
            shared,
        );
    });
});

describe('Ed25519', () => {
    const { seed, publicKey, message, signature } = vectors.ed25519;

    it('derives the same public key from the seed', () => {
        expect(bytesToHex(ed25519.getPublicKey(hexToBytes(seed)))).toBe(publicKey);
    });

    it('produces the same deterministic signature', () => {
        expect(bytesToHex(ed25519.sign(hexToBytes(message), hexToBytes(seed)))).toBe(signature);
    });

    it('verifies a signature libsodium produced', () => {
        expect(ed25519.verify(hexToBytes(signature), hexToBytes(message), hexToBytes(publicKey))).toBe(true);
    });
});

describe('fixture integrity', () => {
    it('covers every primitive the design depends on', () => {
        // A vector quietly disappearing would weaken the cross-check without
        // failing anything.
        expect(Object.keys(vectors).sort()).toEqual([
            '_comment',
            'aad',
            'argon2id',
            'blake2b256',
            'ed25519',
            'hkdf_sha256',
            'x25519',
            'xchacha20poly1305',
        ]);
    });

    it('uses the UTF-8 payload that would expose an encoding mistake', () => {
        expect(new TextDecoder().decode(hexToBytes(vectors.xchacha20poly1305.plaintext))).toContain('🔐');
        expect(utf8ToBytes('🔐')).toHaveLength(4);
    });
});
