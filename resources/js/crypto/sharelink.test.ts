/**
 * One-time share links: the key that is meant to leave.
 *
 * Everything else in this crypto core is about keeping key material contained.
 * A share link inverts that — the key travels to a stranger — so the properties
 * worth testing are different: that the payload is bound to its own token, that
 * a link cannot be opened with anything but its own key, and that the fragment
 * survives being pasted around and refuses anything that has been mangled.
 */
import { describe, expect, it } from 'vitest';

import { IntegrityError, InvalidParameterError } from './errors';
import { hash256 } from './primitives';
import {
    decodeFragment,
    encodeFragment,
    generateLinkCredentials,
    linkSubject,
    LINK_KEY_LENGTH,
    openLink,
    sealLink,
    shareUrl,
    tokenHash,
    TOKEN_LENGTH,
} from './sharelink';

const PAYLOAD_VERSION = 2;

function plaintext(value = 'hunter2'): Uint8Array {
    return new TextEncoder().encode(JSON.stringify({ type: 'password', value }));
}

describe('sealing and opening', () => {
    it('round-trips a payload through a fragment and back', () => {
        const credentials = generateLinkCredentials();
        const sealed = sealLink(credentials, plaintext(), PAYLOAD_VERSION);

        // Exactly what a recipient does: parse the fragment, then decrypt.
        const recovered = decodeFragment(encodeFragment(credentials));

        expect(openLink(recovered, sealed, PAYLOAD_VERSION)).toEqual(plaintext());
    });

    it('generates credentials of the declared sizes', () => {
        const { token, key } = generateLinkCredentials();

        expect(token).toHaveLength(TOKEN_LENGTH);
        expect(key).toHaveLength(LINK_KEY_LENGTH);
    });

    it('cannot be opened with a different link’s key', () => {
        const mine = generateLinkCredentials();
        const theirs = generateLinkCredentials();
        const sealed = sealLink(mine, plaintext(), PAYLOAD_VERSION);

        expect(() => openLink(theirs, sealed, PAYLOAD_VERSION)).toThrow(IntegrityError);
    });

    /*
     | The AAD subject is derived from the token, so a payload is bound to the
     | exact link it belongs to. Substituting one link's ciphertext for another's
     | fails even in the case a server would find easiest to arrange: it holds
     | every payload and every hash, and it still cannot make one open as
     | another.
     */
    it('refuses a payload served under a different token', () => {
        const credentials = generateLinkCredentials();
        const sealed = sealLink(credentials, plaintext(), PAYLOAD_VERSION);

        const substituted = { token: generateLinkCredentials().token, key: credentials.key };

        expect(() => openLink(substituted, sealed, PAYLOAD_VERSION)).toThrow(IntegrityError);
    });

    it('refuses a payload relabelled as a different schema version', () => {
        const credentials = generateLinkCredentials();
        const sealed = sealLink(credentials, plaintext(), PAYLOAD_VERSION);

        expect(() => openLink(credentials, sealed, 1)).toThrow(IntegrityError);
    });

    it('detects a payload altered in storage', () => {
        const credentials = generateLinkCredentials();
        const sealed = sealLink(credentials, plaintext(), PAYLOAD_VERSION);

        // Non-null: a sealed envelope is never empty.
        sealed[sealed.length - 1]! ^= 0x01;

        expect(() => openLink(credentials, sealed, PAYLOAD_VERSION)).toThrow(IntegrityError);
    });
});

describe('the subject, and what the server is told', () => {
    /*
     | Derived rather than transmitted, for the same reason a file chunk's nonce
     | is derived: a value the server supplies is a value the server can
     | substitute. Both ends compute it from the token, which the server never
     | holds.
     */
    it('derives the same subject on both sides, from the token alone', () => {
        const { token } = generateLinkCredentials();

        expect(linkSubject(token)).toBe(linkSubject(Uint8Array.from(token)));
        expect(linkSubject(token)).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
    });

    it('gives different tokens different subjects', () => {
        expect(linkSubject(generateLinkCredentials().token)).not.toBe(
            linkSubject(generateLinkCredentials().token),
        );
    });

    /*
     | What the server stores is a one-way function of the bearer token, and of
     | the *bytes* rather than any textual encoding of them — the same trap as
     | canonicalising a signed payload, and the reason `ShareToken::hash` decodes
     | before hashing.
     */
    it('hashes the token bytes, matching what the server recomputes', () => {
        const { token } = generateLinkCredentials();

        expect(tokenHash(token)).toEqual(hash256(token));
        expect(tokenHash(token)).toHaveLength(32);
    });
});

describe('the fragment', () => {
    it('is url-safe, so it survives being pasted anywhere', () => {
        for (let attempt = 0; attempt < 25; attempt++) {
            expect(encodeFragment(generateLinkCredentials())).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
        }
    });

    it('builds a URL with everything secret after the hash', () => {
        const credentials = generateLinkCredentials();
        const url = shareUrl('https://vault.example', credentials);
        const [origin, fragment] = url.split('#');

        // The path the server sees carries nothing at all.
        expect(origin).toBe('https://vault.example/s');
        expect(fragment).toBe(encodeFragment(credentials));
    });

    it('tolerates a leading hash and surrounding whitespace', () => {
        const credentials = generateLinkCredentials();
        const fragment = encodeFragment(credentials);

        expect(decodeFragment(`#${fragment}`)).toEqual(credentials);
        expect(decodeFragment(`  ${fragment}\n`)).toEqual(credentials);
    });

    /*
     | Long URLs get broken by chat clients, mail readers and terminals, and the
     | resulting failure is not the recipient's fault. Every malformed case says
     | the same practical thing rather than describing an encoding, because the
     | remedy is always "ask for it again".
     */
    it('refuses a truncated or mangled link with an actionable message', () => {
        const fragment = encodeFragment(generateLinkCredentials());

        expect(() => decodeFragment('')).toThrow(/incomplete/);
        expect(() => decodeFragment(fragment.split('.')[0] ?? '')).toThrow(/incomplete/);
        expect(() => decodeFragment(`${fragment}.extra`)).toThrow(/incomplete/);
        expect(() => decodeFragment(fragment.slice(0, -4))).toThrow(/incomplete/);
        expect(() => decodeFragment(`${fragment}!!`)).toThrow(InvalidParameterError);
    });

    it('refuses a fragment whose halves are the wrong size', () => {
        expect(() => decodeFragment('AAAA.BBBB')).toThrow(/incomplete/);
    });
});
