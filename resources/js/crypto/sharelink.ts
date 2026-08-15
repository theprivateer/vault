/**
 * One-time share links: handing a single secret to somebody with no account.
 *
 * **This is the one key in the system that is meant to leave the device.**
 * Everywhere else, a key living outside the Worker would be a defect; here the
 * whole point is that the key travels to a stranger, in a URL, and the design
 * question is not how to keep it in but where to put it so the server never
 * sees it. So this module is deliberately outside the Worker: a link key exists
 * on the main thread, goes into a string, and is shown to a human. Saying that
 * plainly is better than a Worker round trip that would imply a containment
 * this feature does not have.
 *
 * The link key is not part of the key hierarchy. It wraps nothing, is derived
 * from nothing, and opens exactly one payload. A vault key never touches a share
 * — which is precisely what per-item keys were for.
 *
 * ## What goes where
 *
 *   https://host/s#<token>.<key>
 *
 * Both halves are in the **fragment**, and that is the whole security argument:
 *
 *  - A fragment is never sent to the server. Not in the request line, not in
 *    `Referer` (which is `no-referrer` here anyway), not in an access log.
 *  - The token is therefore a bearer credential the server only ever receives in
 *    a request **body**, which nothing logs by default. Had the token been a
 *    path segment — `/s/{token}`, as the original specification had it — every
 *    reverse proxy in front of this application would have written it to disk in
 *    the clear, and the security requirement that logs contain no token would
 *    have been a hope rather than a property.
 *  - The server stores `BLAKE2b(token)`, so the database is not enough to redeem
 *    a link either.
 *
 * There is a second, unplanned benefit, and it is large. A chat client that
 * unfurls a link fetches `GET /s` with no fragment, so it **cannot consume a
 * view**. Under the path-token design the preview fetcher would have burned the
 * single view before the recipient ever clicked.
 */
import type { AadParams } from './aad';
import { open, seal } from './envelope';
import { InvalidParameterError } from './errors';
import { hash256, randomBytes } from './primitives';

/** Bearer credential. 32 bytes, so guessing is not a strategy. */
export const TOKEN_LENGTH = 32;

/** The symmetric key the payload is sealed under. */
export const LINK_KEY_LENGTH = 32;

/** Separates the two fragment fields. Neither half can contain it. */
const FRAGMENT_SEPARATOR = '.';

export interface LinkCredentials {
    token: Uint8Array;
    key: Uint8Array;
}

/** What the creator posts, and what the recipient later receives back. */
export interface SealedLink {
    /** `BLAKE2b-256(token)`. The only form of the token the server ever holds. */
    tokenHash: string;
    payloadCt: string;
}

export function generateLinkCredentials(): LinkCredentials {
    return { token: randomBytes(TOKEN_LENGTH), key: randomBytes(LINK_KEY_LENGTH) };
}

/**
 * The AAD subject for a share link, derived from its token.
 *
 * **Derived rather than transmitted**, for the same reason a file chunk's nonce
 * is: a value the server supplies is a value the server can substitute, and the
 * rule in this codebase is that the client builds every AAD from something the
 * server did not choose. Both ends know the token — the creator minted it, the
 * recipient read it out of the fragment — so neither has to be told.
 *
 * It is shaped like a UUID because `buildAad` requires one, and it is emphatically
 * *not* the `share_links.uuid` column: that identifies the row for the server,
 * this identifies the payload for the cipher, and conflating them would hand the
 * server the input it must not have.
 */
export function linkSubject(token: Uint8Array): string {
    const digest = hash256(token);
    const hex = Array.from(digest.subarray(0, 16), (byte) => byte.toString(16).padStart(2, '0')).join('');

    return [hex.slice(0, 8), hex.slice(8, 12), hex.slice(12, 16), hex.slice(16, 20), hex.slice(20, 32)].join(
        '-',
    );
}

export function tokenHash(token: Uint8Array): Uint8Array {
    return hash256(token);
}

/** Built in one place so sealing and opening cannot drift apart. */
function linkAad({ token }: LinkCredentials, payloadVersion: number): AadParams {
    return {
        context: 'sharelink.payload',
        subject: linkSubject(token),
        version: payloadVersion,
    };
}

/**
 * Seals one secret's plaintext under a fresh link key.
 *
 * The payload is re-encrypted rather than re-served: the stored ciphertext is
 * under an Item Key wrapped by the Vault Key, and handing a stranger anything
 * that opens with a vault key would turn a one-secret share into a whole-vault
 * share. This is the concrete reason the design has per-item keys at all.
 */
export function sealLink(
    credentials: LinkCredentials,
    plaintext: Uint8Array,
    payloadVersion: number,
): Uint8Array {
    return seal(credentials.key, plaintext, linkAad(credentials, payloadVersion));
}

/**
 * Opens a link payload with the key from the fragment.
 *
 * Throws on failure like every other decryption here. A recipient shown an
 * empty box would have no way to tell "this link was tampered with" from "the
 * sender sent nothing".
 */
export function openLink(
    credentials: LinkCredentials,
    envelope: Uint8Array,
    payloadVersion: number,
): Uint8Array {
    return open(credentials.key, envelope, linkAad(credentials, payloadVersion));
}

/**
 * Builds the fragment half of a share URL.
 *
 * Base64url, so the whole thing survives being pasted into a chat window, an
 * email client that reflows text, or a terminal.
 */
export function encodeFragment({ token, key }: LinkCredentials): string {
    return `${base64url(token)}${FRAGMENT_SEPARATOR}${base64url(key)}`;
}

/**
 * Reads a fragment back into credentials.
 *
 * Every failure is the same user-visible situation — the link was truncated by
 * something in the middle, which happens to long URLs in chat clients and email
 * — so the messages say that rather than describing an encoding.
 */
export function decodeFragment(fragment: string): LinkCredentials {
    const cleaned = fragment.replace(/^#/, '').trim();
    const parts = cleaned.split(FRAGMENT_SEPARATOR);

    if (parts.length !== 2) {
        throw new InvalidParameterError(
            'This link is incomplete. Links are often broken by chat clients and email — ask the ' +
                'sender for it again, ideally as plain text.',
        );
    }

    // Non-null: the length check above is what guarantees both halves exist.
    // Coalescing to an empty string instead would add a branch no input can
    // take, and hide that the bound is already proven.
    const [tokenPart, keyPart] = parts;

    return {
        token: fromBase64url(tokenPart!, TOKEN_LENGTH),
        key: fromBase64url(keyPart!, LINK_KEY_LENGTH),
    };
}

/** The complete URL, assembled where the reasoning about it lives. */
export function shareUrl(origin: string, credentials: LinkCredentials): string {
    return `${origin}/s#${encodeFragment(credentials)}`;
}

function base64url(bytes: Uint8Array): string {
    let binary = '';

    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }

    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromBase64url(value: string, expectedLength: number): Uint8Array {
    if (!/^[A-Za-z0-9_-]+$/.test(value)) {
        throw new InvalidParameterError(
            'This link is not in the expected form. Ask the sender for it again.',
        );
    }

    const padded = value.replace(/-/g, '+').replace(/_/g, '/');
    const binary = atob(padded.padEnd(Math.ceil(padded.length / 4) * 4, '='));
    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));

    if (bytes.length !== expectedLength) {
        throw new InvalidParameterError(
            'This link is incomplete. Links are often broken by chat clients and email — ask the ' +
                'sender for it again, ideally as plain text.',
        );
    }

    return bytes;
}
