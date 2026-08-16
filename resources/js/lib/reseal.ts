/**
 * Re-sealing a vault's payloads at the current envelope version.
 *
 * The plaintext is untouched. Each item is opened, a fresh Item Key is
 * generated, and the *same bytes* are sealed again — so this is a migration of
 * the envelope around the data rather than a change to the data. Everything
 * interesting here is about making sure that stays true.
 *
 * **`previousDigest` is the guard, and without it this module is a data-loss
 * bug.** A tab that opened a vault an hour ago holds plaintext that may since
 * have been edited elsewhere; re-sealing it would write the old value back under
 * a new envelope, and every check downstream would pass. The digest of the
 * ciphertext each payload was decrypted from travels with the re-seal, and the
 * server applies the write only while the row still holds it.
 *
 * Framework-free so the decisions can be tested directly rather than through a
 * component.
 */
import type { CryptoClient } from '@/crypto/worker/client';
import { hash256 } from '@/crypto/primitives';

import { fromBase64, toBase64 } from './bytes';
import { ENVELOPE_VERSION } from '@/crypto/envelope';
import type { AadContext } from '@/crypto/aad';
import { PAYLOAD_VERSION, sealItem, type EncryptedItem } from './items';

/** One row on its way to the current envelope version. */
export interface ResealItem {
    uuid: string;
    previous_digest: string;
    payload_ct: string;
    wrapped_item_key: string;
    payload_version: number;
}

/** A decrypted record, paired with the context its payload is bound to. */
export interface ResealCandidate<P> {
    record: EncryptedItem;
    context: AadContext;
    payload: P;
}

/**
 * Whether a stored envelope is behind the version this build writes.
 *
 * Reads the first byte of the decoded ciphertext, which is the public version
 * header — the same two bytes the server validates on the way in. A malformed or
 * unreadable value answers `false`: something this client cannot parse is not
 * something it should re-seal, because re-sealing needs a successful decrypt
 * first and that would have failed anyway.
 */
export function isLegacyEnvelope(payloadCt: string): boolean {
    try {
        const bytes = fromBase64(payloadCt);

        return bytes.length > 0 && bytes[0]! < ENVELOPE_VERSION;
    } catch {
        return false;
    }
}

/**
 * Everything in a vault that would move, given what could be decrypted.
 *
 * An item that failed to open is excluded rather than reported: re-sealing needs
 * plaintext, and a payload this browser could not read is one it must not
 * rewrite. Those show on the page as unreadable, which is a different problem
 * with a different answer.
 */
export function needsReseal<P>(candidates: ReadonlyArray<ResealCandidate<P>>): Array<ResealCandidate<P>> {
    return candidates.filter((candidate) => isLegacyEnvelope(candidate.record.payloadCt));
}

/**
 * Re-seals one item, binding the result to the ciphertext it replaces.
 *
 * `sealItem` is reused rather than reimplemented, so a re-seal produces exactly
 * what a write produces — a fresh Item Key, a padded payload, the same AAD. If
 * the two ever diverged, the migration would quietly write rows in a shape
 * nothing else in the application creates.
 */
export async function resealItem<P>(
    client: CryptoClient,
    vaultUuid: string,
    candidate: ResealCandidate<P>,
): Promise<ResealItem> {
    const sealed = await sealItem(
        client,
        vaultUuid,
        candidate.context,
        candidate.record.uuid,
        candidate.payload,
    );

    return {
        uuid: candidate.record.uuid,
        previous_digest: toBase64(hash256(fromBase64(candidate.record.payloadCt))),
        payload_ct: sealed.payload_ct,
        wrapped_item_key: sealed.wrapped_item_key,
        payload_version: PAYLOAD_VERSION,
    };
}

/**
 * Splits a list into batches the server will accept.
 *
 * A re-seal is independent per row — both envelope versions open, so every row
 * is correct on its own — which is what makes batching safe here and not safe
 * for a re-key. A vault of a thousand items becomes five requests, any of which
 * may fail without leaving anything to repair.
 */
export function batched<T>(items: readonly T[], size: number): T[][] {
    const batches: T[][] = [];

    for (let start = 0; start < items.length; start += size) {
        batches.push(items.slice(start, start + size));
    }

    return batches;
}

/** Matches `items.*` max in ResealVaultRequest. */
export const RESEAL_BATCH_SIZE = 200;
