/**
 * Known-answer tests against published RFC vectors.
 *
 * The scope here is deliberate: these verify that *we* wired the primitives up
 * correctly — right curve, right argument order, right byte order. Verifying
 * that ChaCha20 is ChaCha20 is `@noble`'s job and its auditors'. See
 * "Deliberately not tested" in docs/06-testing-and-ci.md.
 *
 * A wiring mistake is exactly the kind of bug that a round-trip test cannot
 * catch, because encrypt and decrypt would agree with each other while both
 * being wrong.
 */
import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { describe, expect, it } from 'vitest';

import { constantTimeEqual, hash256 } from './primitives';

describe('X25519 (RFC 7748 §6.1)', () => {
    const alice = {
        secret: hexToBytes('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a'),
        public: '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a',
    };

    const bob = {
        secret: hexToBytes('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb'),
        public: 'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f',
    };

    const sharedSecret = '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742';

    it('derives the published public keys', () => {
        expect(bytesToHex(x25519.getPublicKey(alice.secret))).toBe(alice.public);
        expect(bytesToHex(x25519.getPublicKey(bob.secret))).toBe(bob.public);
    });

    it('agrees on the published shared secret in both directions', () => {
        expect(bytesToHex(x25519.getSharedSecret(alice.secret, hexToBytes(bob.public)))).toBe(sharedSecret);
        expect(bytesToHex(x25519.getSharedSecret(bob.secret, hexToBytes(alice.public)))).toBe(sharedSecret);
    });
});

describe('Ed25519 (RFC 8032 §7.1)', () => {
    const secret = hexToBytes('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60');
    const publicKey = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a';
    const signature =
        'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b';

    it('derives the published public key', () => {
        expect(bytesToHex(ed25519.getPublicKey(secret))).toBe(publicKey);
    });

    it('produces the published signature over an empty message', () => {
        expect(bytesToHex(ed25519.sign(new Uint8Array(0), secret))).toBe(signature);
    });

    it('verifies the published signature', () => {
        expect(ed25519.verify(hexToBytes(signature), new Uint8Array(0), hexToBytes(publicKey))).toBe(true);
    });

    it('rejects the signature over a different message', () => {
        expect(ed25519.verify(hexToBytes(signature), new Uint8Array([0]), hexToBytes(publicKey))).toBe(false);
    });
});

describe('HKDF-SHA256 (RFC 5869 test case 1)', () => {
    it('expands to the published output', () => {
        const okm = hkdf(
            sha256,
            hexToBytes('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b'),
            hexToBytes('000102030405060708090a0b0c'),
            hexToBytes('f0f1f2f3f4f5f6f7f8f9'),
            42,
        );

        expect(bytesToHex(okm)).toBe(
            '3cb25f25faacd57a90434f64d0362f2a' + '2d2d0a90cf1a5a4c5db02d56ecc4c5bf' + '34007208d5b887185865',
        );
    });
});

describe('ChaCha20-Poly1305 (RFC 8439 §2.8.2)', () => {
    /*
     | The envelope uses XChaCha20-Poly1305 for its 192-bit nonce, which is
     | XChaCha's HChaCha20 step followed by exactly this construction. Pinning
     | the RFC vector for the underlying AEAD confirms the AAD parameter is
     | wired to associated data and not to something else.
     */
    const key = hexToBytes('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f');
    const nonce = hexToBytes('070000004041424344454647');
    const aad = hexToBytes('50515253c0c1c2c3c4c5c6c7');
    const plaintext = new TextEncoder().encode(
        "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.",
    );

    const expected =
        'd31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6' +
        '3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36' +
        '92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc' +
        '3ff4def08e4b7a9de576d26586cec64b6116' +
        '1ae10b594f09e26a7e902ecbd0600691';

    it('produces the published ciphertext and tag', () => {
        expect(bytesToHex(chacha20poly1305(key, nonce, aad).encrypt(plaintext))).toBe(expected);
    });

    it('rejects the ciphertext when the associated data differs', () => {
        const tampered = hexToBytes('50515253c0c1c2c3c4c5c6c8');

        expect(() => chacha20poly1305(key, nonce, tampered).decrypt(hexToBytes(expected))).toThrow();
    });
});

describe('BLAKE2b-256', () => {
    it('hashes the empty input to the published digest', () => {
        expect(bytesToHex(hash256(new Uint8Array(0)))).toBe(
            '0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8',
        );
    });

    it('hashes "abc" to the published digest', () => {
        expect(bytesToHex(hash256(new TextEncoder().encode('abc')))).toBe(
            'bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319',
        );
    });
});

describe('constantTimeEqual', () => {
    it('matches identical arrays', () => {
        expect(constantTimeEqual(hexToBytes('00ff10'), hexToBytes('00ff10'))).toBe(true);
    });

    it.each([
        ['80ff10', 'first bit'],
        ['00ff11', 'last bit'],
        ['01ff10', 'a middle byte'],
    ])('rejects a difference in %s', (other) => {
        expect(constantTimeEqual(hexToBytes('00ff10'), hexToBytes(other))).toBe(false);
    });

    it('rejects differing lengths', () => {
        expect(constantTimeEqual(hexToBytes('00ff'), hexToBytes('00ff10'))).toBe(false);
        expect(constantTimeEqual(new Uint8Array(0), hexToBytes('00'))).toBe(false);
    });

    it('matches two empty arrays', () => {
        expect(constantTimeEqual(new Uint8Array(0), new Uint8Array(0))).toBe(true);
    });
});
