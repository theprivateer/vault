/**
 * Taking everything out (Phase 12, task 3).
 *
 * This exists because of D3. An application that will permanently destroy your
 * data rather than hand it to somebody who is not you owes you an unambiguous
 * way to leave with it, and "you can read it through the interface" is not one.
 * The export is what makes "there is no recovery path" a defensible position
 * rather than a hostage situation.
 *
 * Three rules shape the module.
 *
 * **The payload is copied verbatim.** A secret is exported as the object that
 * came out of the decrypt, not as a set of fields this build recognises. That is
 * the same reasoning as `unmappedFields` in secretTypes.ts, applied where it
 * matters most: an export that silently dropped a key written by a later build
 * would be the last copy of that data, and nobody would find out.
 *
 * **What is left out is written down.** Every export carries an `omissions`
 * list. A file too large to inline, version history, the audit log — each is
 * named in the document with its reason, so the archive says what it is rather
 * than being quietly partial.
 *
 * **The plaintext form leads with the warning.** JSON preserves key order, so
 * the first thing in the file is several lines saying that every password in it
 * is now sitting unencrypted on a disk. It is the correct format to offer and
 * the wrong one to store.
 */
import { sealArchive } from '@/crypto/archive';
import type { CryptoClient } from '@/crypto/worker/client';

import { toBase64 } from './bytes';
import { openAll, openVault, type ProgressCallback } from './decrypt';
import { downloadFile, type FileManifest, type FileRecord } from './files';
import { getJson } from './http';
import type {
    LockboxPayload,
    LockboxRecord,
    SecretPayload,
    SecretRecord,
    VaultPayload,
    VaultRecord,
} from './items';
import { uuid7 } from './uuid';

/** Names the shape of the document, so a reader knows what they have. */
export const EXPORT_FORMAT = 'vault.export';

/** The document's own schema version, independent of the archive format's. */
export const EXPORT_VERSION = 1;

/**
 * How many bytes of attachment the archive will carry.
 *
 * A budget rather than a per-file limit, because what actually breaks is the
 * whole document: it is assembled as one string, base64 costs a third again on
 * top of the plaintext, and a vault at its 500 MiB quota would take the tab down
 * somewhere in the middle of a long decrypt with nothing written out.
 *
 * Files are considered in document order and inlined while the budget lasts.
 * Anything that does not fit is listed with its size and its hash — present in
 * the manifest, absent in body, and named in `omissions` — because a file that
 * vanished with no trace is the failure this whole module is against.
 */
export const INLINE_BUDGET_BYTES = 25 * 1024 * 1024;

/** A secret, as it came out of the decrypt. */
export interface ExportSecret {
    uuid: string;
    updatedAt: string | null;
    /** Verbatim. Unrecognised keys included, by design. */
    payload: SecretPayload | null;
    /** Set exactly when `payload` is null. Never silently dropped. */
    error?: string;
}

export interface ExportFile {
    uuid: string;
    filename: string;
    mime: string;
    bytes: number;
    sha256: string;
    /** base64 of the plaintext, or null when the budget did not reach it. */
    body: string | null;
    /** Why `body` is null. Absent when it is not. */
    omitted?: string;
    error?: string;
}

export interface ExportLockbox {
    uuid: string;
    payload: LockboxPayload | null;
    error?: string;
    secrets: ExportSecret[];
    files: ExportFile[];
}

export interface ExportVault {
    uuid: string;
    role: 'owner' | 'editor' | 'viewer';
    /** True when somebody else owns it, so the reader knows whose data this is. */
    shared: boolean;
    payload: VaultPayload | null;
    error?: string;
    lockboxes: ExportLockbox[];
}

export interface ExportDocument {
    format: typeof EXPORT_FORMAT;
    version: number;
    exportedAt: string;
    /** Present only in the plaintext form, where it is the first thing read. */
    warning?: string[];
    account: { handle: string };
    omissions: string[];
    vaults: ExportVault[];
}

/**
 * What the plaintext file says before it says anything else.
 *
 * Deliberately not softened. Somebody who downloads this has, in one click,
 * undone every property the rest of this application exists to provide, and the
 * only useful thing the file can do is say so where it cannot be missed.
 */
export const PLAINTEXT_WARNING: readonly string[] = [
    'THIS FILE IS NOT ENCRYPTED.',
    'Every password, key, card number and note below is readable by anything that can read this file — ' +
        'other programs on this computer, a backup service, whoever finds the disk.',
    'It is not protected by your master password. Deleting it does not reliably erase it: a copy may ' +
        'survive in the Trash, in a Time Machine snapshot, in a cloud sync folder, or in free space.',
    'Use it, then destroy it. If you want a copy to keep, take the encrypted archive instead.',
];

interface FileCandidate {
    record: FileRecord;
    manifest: FileManifest | null;
    error: string | null;
}

/**
 * A decision about one attachment.
 *
 * A union rather than a boolean and an optional string, so that "left out"
 * cannot exist without the reason it was left out. The reason is written into
 * the document beside the file, and a missing one would be exactly the silent
 * omission this module exists to prevent.
 */
export type FilePlan =
    { candidate: FileCandidate; inline: true } | { candidate: FileCandidate; inline: false; reason: string };

/**
 * Decides which attachments fit, in document order.
 *
 * Split out from the fetching so the rule can be tested without a network or a
 * Worker — the arithmetic is the part that decides whether somebody's data
 * leaves with them, and it should not need an integration test to check.
 */
export function planInlineFiles(
    candidates: readonly FileCandidate[],
    budget: number = INLINE_BUDGET_BYTES,
): FilePlan[] {
    let remaining = budget;

    return candidates.map((candidate) => {
        if (!candidate.manifest) {
            return { candidate, inline: false, reason: 'its manifest could not be decrypted' };
        }

        const size = candidate.manifest.plaintextSize;

        if (size > remaining) {
            return {
                candidate,
                inline: false,
                reason:
                    `it is ${formatBytes(size)} and the archive inlines ${formatBytes(budget)} of attachments; ` +
                    'download it from the vault separately',
            };
        }

        remaining -= size;

        return { candidate, inline: true };
    });
}

function formatBytes(bytes: number): string {
    if (bytes < 1024) {
        return `${bytes} bytes`;
    }

    const units = ['KiB', 'MiB', 'GiB'];
    let value = bytes / 1024;
    let unit = 0;

    while (value >= 1024 && unit < units.length - 1) {
        value /= 1024;
        unit += 1;
    }

    return `${value >= 10 ? Math.round(value) : value.toFixed(1)} ${units[unit]}`;
}

/**
 * The things this export does not contain, and why.
 *
 * Version history is the one worth reading twice. It is left out on purpose
 * rather than for effort: superseded payloads are old credentials, a vault's
 * retention policy exists to stop them accumulating, and an export that swept
 * them up would put every rotated password back into circulation in a file with
 * no retention policy at all.
 */
export function standardOmissions(): string[] {
    return [
        'Version history. Superseded payloads are credentials that were rotated, often because they ' +
            'leaked; a vault expires them on a schedule and this file would not.',
        'The audit log. It is a record of what happened, not data you put in, and it is readable at ' +
            '/account/activity while the server is running.',
        'Share links, invitations and fingerprint pins. Each is a live piece of server state rather ' +
            'than something an archive could restore.',
        'Your keys. A recovery kit unlocks this account; an archive is opened with its own passphrase ' +
            'and needs nothing else, which is what lets it outlive the account.',
    ];
}

export interface ExportInput {
    handle: string;
    vaults: ExportVault[];
    omissions: string[];
    exportedAt?: Date;
}

export function buildExportDocument({ handle, vaults, omissions, exportedAt }: ExportInput): ExportDocument {
    return {
        format: EXPORT_FORMAT,
        version: EXPORT_VERSION,
        exportedAt: (exportedAt ?? new Date()).toISOString(),
        account: { handle },
        omissions,
        vaults,
    };
}

/**
 * The plaintext form: the same document with the warning welded to the front.
 *
 * `warning` is inserted rather than being a field of every document, because the
 * encrypted archive does not need it — the whole point of that file is that
 * reading it costs a passphrase.
 */
export function serialisePlaintext(document: ExportDocument): string {
    const { format, version, exportedAt, ...rest } = document;

    return `${JSON.stringify({ format, version, exportedAt, warning: PLAINTEXT_WARNING, ...rest }, null, 2)}\n`;
}

export function serialiseArchivePlaintext(document: ExportDocument): string {
    return `${JSON.stringify(document, null, 2)}\n`;
}

/**
 * A filename that sorts, dates itself and says what it is.
 *
 * The archive takes `.vaultarchive` rather than `.json.enc` or `.bin` so that a
 * file found in five years announces which program made it. Its first eight
 * bytes say the same thing to `file` and to a hex editor.
 */
export function exportFilename(kind: 'archive' | 'plaintext', at: Date = new Date()): string {
    const date = at.toISOString().slice(0, 10);

    return kind === 'archive' ? `vault-export-${date}.vaultarchive` : `vault-export-${date}.PLAINTEXT.json`;
}

/**
 * Encrypts a finished document.
 *
 * A thin wrapper, and it earns its place by being the only route from a document
 * to a file: the UUID is generated here, so no caller can produce an archive
 * that reuses another's identity.
 */
export function encryptExport(document: ExportDocument, passphrase: string): Uint8Array {
    return sealArchive(passphrase, new TextEncoder().encode(serialiseArchivePlaintext(document)), uuid7());
}

/** What the server sends back for the whole account. */
export interface ExportBundle {
    handle: string;
    vaults: Array<{
        vault: VaultRecord;
        lockboxes: LockboxRecord[];
        secrets: SecretRecord[];
        files: FileRecord[];
    }>;
}

export function fetchExportBundle(): Promise<ExportBundle> {
    return getJson<ExportBundle>('/account/export/data');
}

export interface RunOptions {
    client: CryptoClient;
    bundle: ExportBundle;
    /** Whether to decrypt and inline attachment bodies at all. */
    includeFiles: boolean;
    budget?: number;
    onProgress?: ProgressCallback;
}

/**
 * Decrypts an entire account into a document.
 *
 * Every failure is recorded on the item it belongs to rather than thrown. An
 * export that abandons the whole run because one secret in one vault does not
 * verify is an export that cannot be taken by exactly the person who most needs
 * to take one — somebody whose data is already partly damaged. The unreadable
 * item appears with its error where its payload would have been, which is the
 * same rule `openAll` follows on a page (SR3).
 */
export async function runExport({
    client,
    bundle,
    includeFiles,
    budget = INLINE_BUDGET_BYTES,
    onProgress,
}: RunOptions): Promise<ExportDocument> {
    const vaults: ExportVault[] = [];
    const omissions = standardOmissions();

    const total = bundle.vaults.reduce(
        (sum, entry) => sum + 1 + entry.lockboxes.length + entry.secrets.length + entry.files.length,
        0,
    );
    let done = 0;

    const advance = (by: number): void => {
        done += by;
        onProgress?.(done, total);
    };

    for (const entry of bundle.vaults) {
        const vault = await openVault<VaultPayload>(client, entry.vault);
        advance(1);

        const exported: ExportVault = {
            uuid: entry.vault.uuid,
            role: entry.vault.membership.role,
            shared: entry.vault.membership.role !== 'owner',
            payload: vault.payload,
            ...(vault.error ? { error: vault.error } : {}),
            lockboxes: [],
        };

        vaults.push(exported);

        // Without the Vault Key nothing below it can be opened, and asking the
        // Worker for a key it does not hold would produce one identical error
        // per item instead of the one that actually happened.
        if (vault.error) {
            advance(entry.lockboxes.length + entry.secrets.length + entry.files.length);
            continue;
        }

        const lockboxes = await openAll<LockboxRecord, LockboxPayload>(
            client,
            entry.vault.uuid,
            'lockbox.payload',
            entry.lockboxes,
            () => 'This lockbox',
        );
        advance(entry.lockboxes.length);

        const secrets = await openAll<SecretRecord, SecretPayload>(
            client,
            entry.vault.uuid,
            'secret.payload',
            entry.secrets,
            () => 'This secret',
        );
        advance(entry.secrets.length);

        const manifests = await openAll<FileRecord, FileManifest>(
            client,
            entry.vault.uuid,
            'file.payload',
            entry.files,
            () => 'This file',
        );

        const plan = planInlineFiles(
            manifests.map((opened) => ({
                record: opened.record,
                manifest: opened.payload,
                error: opened.error,
            })),
            includeFiles ? budget : 0,
        );

        const files: Array<{ lockboxUuid: string; file: ExportFile }> = [];

        for (const planned of plan) {
            files.push({
                lockboxUuid: planned.candidate.record.lockboxUuid,
                file: await exportOneFile(client, entry.vault.uuid, planned),
            });
            advance(1);
        }

        for (const lockbox of lockboxes) {
            const uuid = lockbox.record.uuid;

            exported.lockboxes.push({
                uuid,
                payload: lockbox.payload,
                ...(lockbox.error ? { error: lockbox.error } : {}),
                secrets: secrets
                    .filter((secret) => secret.record.lockboxUuid === uuid)
                    .map((secret) => ({
                        uuid: secret.record.uuid,
                        updatedAt: secret.record.updatedAt,
                        payload: secret.payload,
                        ...(secret.error ? { error: secret.error } : {}),
                    })),
                files: files.filter((held) => held.lockboxUuid === uuid).map((held) => held.file),
            });
        }
    }

    if (!includeFiles) {
        omissions.unshift(
            'Attachment contents. You chose not to include them; their names and sizes are listed.',
        );
    }

    return buildExportDocument({ handle: bundle.handle, vaults, omissions });
}

async function exportOneFile(
    client: CryptoClient,
    vaultUuid: string,
    planned: FilePlan,
): Promise<ExportFile> {
    const { record, manifest, error } = planned.candidate;

    if (!manifest) {
        return {
            uuid: record.uuid,
            filename: '(unreadable)',
            mime: '',
            bytes: 0,
            sha256: '',
            body: null,
            omitted: planned.inline ? 'its manifest could not be decrypted' : planned.reason,
            ...(error ? { error } : {}),
        };
    }

    const described: ExportFile = {
        uuid: record.uuid,
        filename: manifest.filename,
        mime: manifest.mime,
        bytes: manifest.plaintextSize,
        sha256: manifest.sha256,
        body: null,
    };

    if (!planned.inline) {
        return { ...described, omitted: planned.reason };
    }

    // An upload still in progress has no complete body to export, and asking
    // for its chunks would fail on the first one the server has not received.
    if (!record.uploadedAt) {
        return { ...described, omitted: 'its upload never finished, so there is no complete copy to take' };
    }

    try {
        const blob = await downloadFile({
            client,
            vaultUuid,
            uuid: record.uuid,
            manifest,
            wrappedItemKey: record.wrappedItemKey,
        });

        return { ...described, body: toBase64(new Uint8Array(await blob.arrayBuffer())) };
    } catch (cause) {
        return {
            ...described,
            omitted: 'it could not be reassembled',
            error: cause instanceof Error ? cause.message : 'The file could not be downloaded.',
        };
    }
}
