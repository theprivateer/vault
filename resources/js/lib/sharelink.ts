/**
 * Creating and opening one-time share links, from the browser's side.
 *
 * The crypto lives in `@/crypto/sharelink`; this is the part that talks to the
 * server, and its whole job is to keep the two halves of a link on the correct
 * sides of that conversation:
 *
 *  - **Creating**, the browser sends the token's *hash*. The server therefore
 *    never holds a redeemable token, not even for the length of one request.
 *  - **Opening**, the browser sends the *token*, and the server hashes it to
 *    find the row. Sending a hash here instead would feel symmetrical and would
 *    be a real weakness: the stored value would become the thing that opens a
 *    link, and anyone who read the database could open every outstanding share.
 *
 * The link key is in neither request. It exists only in the fragment, which no
 * browser transmits.
 */
import { openLink, sealLink, tokenHash, type LinkCredentials } from '@/crypto/sharelink';

import { toBase64 } from './bytes';
import { postJson } from './http';
import { PAYLOAD_VERSION, type SecretPayload } from './items';
import { pad, unpad } from '@/crypto/padding';
import { decodeUtf8, encodeUtf8, fromBase64 } from './bytes';
import { uuid7 } from './uuid';

/** What the creator's page needs back after making a link. */
export interface CreatedLink {
    uuid: string;
    credentials: LinkCredentials;
}

export interface LinkOptions {
    expiresInHours: number;
    maxViews: number;
}

/** One row in the creator's list of outstanding links. */
export interface ShareLinkRecord {
    uuid: string;
    secretUuid: string | null;
    expiresAt: string;
    maxViews: number;
    viewCount: number;
    revokedAt: string | null;
    createdAt: string;
    redeemable: boolean;
}

/**
 * Seals a secret under a fresh link key and registers it.
 *
 * The payload is padded exactly as a stored item is, so a share does not leak
 * the length of the credential it carries — a one-character password and a
 * forty-character one produce the same sized row. It would have been easy to
 * skip: the padding lives in `sealItem`, and this path does not go through it.
 */
export async function createShareLink(
    secretUuid: string,
    payload: SecretPayload,
    options: LinkOptions,
    credentials: LinkCredentials,
): Promise<CreatedLink> {
    const uuid = uuid7();

    const sealed = sealLink(credentials, pad(encodeUtf8(JSON.stringify(payload))), PAYLOAD_VERSION);

    await postJson(`/secrets/${secretUuid}/links`, {
        uuid,
        token_hash: toBase64(tokenHash(credentials.token)),
        payload_ct: toBase64(sealed),
        payload_version: PAYLOAD_VERSION,
        expires_in_hours: options.expiresInHours,
        max_views: options.maxViews,
    });

    return { uuid, credentials };
}

export interface RevealedLink {
    payload: SecretPayload;
    viewsRemaining: number;
}

/**
 * Redeems a link and decrypts what comes back.
 *
 * **This consumes a view.** The server counts before it answers, so calling it
 * twice spends two — which is why the recipient page calls it exactly once, on
 * a deliberate action, and never on mount or in a retry.
 */
export async function revealShareLink(credentials: LinkCredentials): Promise<RevealedLink> {
    const response = await postJson<{
        payloadCt: string;
        payloadVersion: number;
        viewsRemaining: number;
    }>('/s/reveal', { token: base64url(credentials.token) });

    const plaintext = openLink(credentials, fromBase64(response.payloadCt), response.payloadVersion);

    return {
        payload: JSON.parse(decodeUtf8(unpad(plaintext))) as SecretPayload,
        viewsRemaining: response.viewsRemaining,
    };
}

/**
 * The token as the reveal endpoint expects it.
 *
 * Duplicated from the crypto module's private helper on purpose: that one
 * encodes for a URL fragment and this one encodes for a request body, and
 * although the alphabets happen to match today, tying the wire format of an API
 * to the display format of a URL is how one of them ends up unable to change.
 */
function base64url(bytes: Uint8Array): string {
    return toBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
