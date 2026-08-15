/**
 * Trust on first use, for other people's public keys.
 *
 * The server serves every public key in this system, so the server can lie about
 * every one of them. A self-signature proves only that whoever holds the private
 * key published both halves together — which a malicious server generating its
 * own keypair satisfies perfectly. The thing that actually detects substitution
 * is a human comparing a fingerprint out of band, once, and this module
 * remembering the answer.
 *
 * Three states, and the third is the whole point:
 *
 * - **Unknown.** Never seen. Show the fingerprint, ask for confirmation.
 * - **Match.** Seen before, unchanged. Proceed without interrupting anyone.
 * - **Changed.** Seen before, and different. Stop. This is what a server
 *   substituting its own key looks like, and it is indistinguishable from the
 *   innocent explanation — the other person rotated or reinstalled — so the only
 *   safe response is to make someone re-verify rather than to guess.
 *
 * The map is encrypted under the User Key before it goes back to the server, so
 * the server can neither read which identities have been checked nor mark its
 * own key as already trusted. It can still drop the row or serve a stale copy;
 * that degrades to a verification prompt, which is safe. Forgetting is
 * survivable, forging is not, and only forging is prevented here.
 */
import { pad, unpad } from '@/crypto/padding';
import type { CryptoClient } from '@/crypto/worker/client';
import { USER_KEY } from '@/crypto/worker/protocol';

import { decodeUtf8, encodeUtf8, fromBase64, toBase64 } from './bytes';

/** Recipient UUID to the fingerprint last verified for them, lowercase hex. */
export type PinMap = Record<string, string>;

const PINS_VERSION = 1;

const FINGERPRINT_PATTERN = /^[0-9a-f]{64}$/;

export type PinVerdict =
    | { status: 'unknown' }
    | { status: 'match' }
    /** `pinned` is what was verified before, for the interstitial to show. */
    | { status: 'changed'; pinned: string };

export function checkPin(pins: PinMap, userUuid: string, fingerprint: string): PinVerdict {
    const pinned = pins[userUuid];

    if (pinned === undefined) {
        return { status: 'unknown' };
    }

    return pinned === fingerprint ? { status: 'match' } : { status: 'changed', pinned };
}

/** Records a verification. Returns a new map rather than mutating the held one. */
export function withPin(pins: PinMap, userUuid: string, fingerprint: string): PinMap {
    return { ...pins, [userUuid]: fingerprint };
}

/**
 * Decrypts the stored pin map.
 *
 * Every value is checked to be a fingerprint. A server cannot forge the
 * ciphertext, but it can serve an old one or a truncated one, and a map that
 * silently contained `undefined` for someone would make `checkPin` answer
 * "unknown" — downgrading a hard stop to a first-sight prompt, which is exactly
 * the outcome an attacker wants. Malformed contents are an error, not a default.
 */
export async function openPins(client: CryptoClient, ownerUuid: string, pinsCt: string): Promise<PinMap> {
    const plaintext = await client.open(USER_KEY, fromBase64(pinsCt), pinsAad(ownerUuid));
    const parsed: unknown = JSON.parse(decodeUtf8(unpad(plaintext)));

    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
        throw new Error('The stored list of verified identities is not readable.');
    }

    const pins: PinMap = {};

    for (const [userUuid, fingerprint] of Object.entries(parsed as Record<string, unknown>)) {
        if (typeof fingerprint !== 'string' || !FINGERPRINT_PATTERN.test(fingerprint)) {
            throw new Error(`The stored list of verified identities is corrupt at ${userUuid}.`);
        }

        pins[userUuid] = fingerprint;
    }

    return pins;
}

/**
 * Encrypts the pin map for storage.
 *
 * Padded like an item payload, because the length of this blob is a direct count
 * of how many people you have verified — which is a piece of the sharing graph
 * the server would otherwise get for free, on a row it holds anyway.
 */
export async function sealPins(client: CryptoClient, ownerUuid: string, pins: PinMap): Promise<string> {
    const envelope = await client.seal(USER_KEY, pad(encodeUtf8(JSON.stringify(pins))), pinsAad(ownerUuid));

    return toBase64(envelope);
}

/**
 * Bound to the owner's own UUID: the pin store belongs to one account, and a
 * server that could hand one user's store to another would be handing over a
 * set of trust decisions they never made.
 */
function pinsAad(ownerUuid: string) {
    return { context: 'user.pins' as const, subject: ownerUuid, version: PINS_VERSION };
}
