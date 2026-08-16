/**
 * A secret's superseded payloads: sealing one, opening them, comparing two.
 *
 * **An archived version is a new encryption, not a copy of the old column.**
 * When an edit replaces a payload, this module re-seals the *outgoing*
 * plaintext under a fresh Item Key, bound to the context
 * `secret.version.payload` and to a brand new UUID, and the browser posts that
 * alongside the replacement.
 *
 * The cheaper design — let the server copy `secrets.payload_ct` into the history
 * table — is the one that must not be built. A copied ciphertext keeps the
 * associated data it was sealed with, which binds it to `secret.payload` at the
 * secret's own UUID: byte-for-byte identical to the binding the live column
 * has. A server holding both could write any archived version back over the
 * live row and every client would verify it happily, silently restoring a
 * password that was rotated *because it leaked*. Adding history is what creates
 * that attack, and the distinct context and subject are what close it (SR4).
 *
 * It costs one extra sealed payload per edit, and it means a secret whose
 * ciphertext no longer verifies cannot be edited at all — an edit must archive
 * what it replaces, and nothing can archive what it could not read. That is
 * stated in the interface rather than worked around.
 */
import type { CryptoClient } from '@/crypto/worker/client';

import { openAll, type Opened, type ProgressCallback } from './decrypt';
import { diffLines, type DiffOp } from './diff';
import { sealItem, type EncryptedItem, type SecretPayload } from './items';
import { ALL_FIELD_KEYS, readField } from './secretTypes';
import { uuid7 } from './uuid';

/** One archived payload, as the server sends it: ciphertext and a timestamp. */
export interface VersionRecord extends EncryptedItem {
    /** The `secrets.current_version` this payload was live at. */
    version: number;
    /** Display name of whoever made the edit that superseded it, if still known. */
    author: string | null;
    createdAt: string;
}

export type OpenedVersion = Opened<VersionRecord, SecretPayload>;

/** The archive half of an update, named as the request expects it. */
export interface SealedVersion {
    version_uuid: string;
    version_payload_ct: string;
    version_wrapped_item_key: string;
    version_payload_version: number;
}

/**
 * Seals the payload an edit is about to replace.
 *
 * Called with the plaintext the page already holds — the version being
 * superseded, never the new one. Getting those the wrong way round would
 * archive the future and overwrite the past, and both payloads are opaque to
 * the server, so nothing downstream could notice.
 */
export async function sealVersion(
    client: CryptoClient,
    vaultUuid: string,
    superseded: SecretPayload,
): Promise<SealedVersion> {
    const uuid = uuid7();

    const sealed = await sealItem(client, vaultUuid, 'secret.version.payload', uuid, superseded);

    return {
        version_uuid: uuid,
        version_payload_ct: sealed.payload_ct,
        version_wrapped_item_key: sealed.wrapped_item_key,
        version_payload_version: sealed.payload_version,
    };
}

/**
 * Decrypts a list of archived payloads.
 *
 * Failures stay attached to the version that failed, as everywhere else: one
 * unreadable entry in a history must not blank out the ten around it, and it
 * must not render as an empty version either — an empty version and a tampered
 * one looking the same is the 2017 bug in a new place (SR3).
 */
export function openVersions(
    client: CryptoClient,
    vaultUuid: string,
    versions: readonly VersionRecord[],
    onProgress?: ProgressCallback,
): Promise<OpenedVersion[]> {
    return openAll<VersionRecord, SecretPayload>(
        client,
        vaultUuid,
        'secret.version.payload',
        versions,
        (record) => `Version ${record.version}`,
        onProgress,
    );
}

/** A payload field, and what happened to it between two versions. */
export interface FieldDiff {
    field: string;
    changed: boolean;
    /** Empty when nothing changed, so a caller can render only what moved. */
    ops: DiffOp[];
}

/**
 * The fields a comparison walks, in the order a reader wants them.
 *
 * A fixed list rather than the union of both objects' keys: a payload written
 * by a future build could carry a field this one knows nothing about, and
 * rendering an unknown key's contents into the page is how a diff view becomes
 * the place where an unexpected value gets displayed unlabelled.
 *
 * Derived from `ALL_FIELD_KEYS` so the structured types are covered without this
 * list being a second place to remember. It stays a closed set either way —
 * every key in it is one some type declares.
 */
const COMPARED: readonly string[] = ['key', 'type', ...ALL_FIELD_KEYS];

/**
 * Compares two decrypted payloads, field by field.
 *
 * `paranoid` is deliberately absent — it is a boolean UI hint and "the sensitive
 * flag changed" is not something a diff needs a text comparison for.
 *
 * A field neither version populates is reported as unchanged rather than
 * skipped, so the caller keeps deciding what to render: `History.vue` filters on
 * `changed`, and a card's version history should not list five empty address
 * fields as evidence that nothing happened to them.
 */
export function comparePayloads(before: SecretPayload, after: SecretPayload): FieldDiff[] {
    return COMPARED.map((field) => {
        const a = readField(before, field);
        const b = readField(after, field);

        return {
            field,
            changed: a !== b,
            ops: a === b ? [] : diffLines(a, b),
        };
    });
}
