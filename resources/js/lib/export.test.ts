/**
 * The export is the last copy, so the tests are shaped around loss.
 *
 * Every case here asks one of two questions: does everything that was in the
 * account come out, and where something could not come out, does the file say
 * so. A partial export that looks complete is the worst failure this module
 * has — worse than throwing, because the person reading it has already deleted
 * the original.
 */
import { describe, expect, it } from 'vitest';

import { openArchive, readArchiveHeader } from '@/crypto/archive';
import { CryptoClient } from '@/crypto/worker/client';
import { installHandler, type WorkerScope } from '@/crypto/worker/handler';
import type { Reply, Request } from '@/crypto/worker/protocol';

import { fromBase64, toBase64 } from './bytes';
import {
    buildExportDocument,
    encryptExport,
    EXPORT_FORMAT,
    exportFilename,
    INLINE_BUDGET_BYTES,
    planInlineFiles,
    PLAINTEXT_WARNING,
    runExport,
    serialiseArchivePlaintext,
    serialisePlaintext,
    standardOmissions,
    type ExportBundle,
} from './export';
import type { FileManifest, FileRecord } from './files';
import {
    loadIdentity,
    PAYLOAD_VERSION,
    sealItem,
    sealNewVault,
    type LockboxRecord,
    type SecretPayload,
    type SecretRecord,
    type VaultRecord,
} from './items';

const USER_UUID = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f6';
const VAULT_UUID = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f7';
const MEMBERSHIP_UUID = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f8';
const LOCKBOX_UUID = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f9';
const FILE_UUID = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5fc';

const FAST_KDF = { m: 8, t: 1, p: 1 };

class FakeWorker {
    onmessage: ((event: MessageEvent<Reply>) => void) | null = null;

    onerror: ((event: unknown) => void) | null = null;

    private readonly scope: WorkerScope;

    constructor() {
        this.scope = {
            onmessage: null,
            postMessage: (reply: Reply) => {
                queueMicrotask(() => this.onmessage?.({ data: reply } as MessageEvent<Reply>));
            },
        };

        installHandler(this.scope);
    }

    postMessage(message: { id: number; request: Request }): void {
        this.scope.onmessage?.({ data: structuredClone(message) });
    }

    terminate(): void {}
}

function client(): CryptoClient {
    return new CryptoClient(() => new FakeWorker() as unknown as Worker);
}

function tamper(base64: string): string {
    const bytes = fromBase64(base64);
    bytes[bytes.length - 1]! ^= 0x01;

    return toBase64(bytes);
}

const uuidAt = (n: number) => `0192f3a1-4b2c-7d3e-8f90-a1b2c3d4${n.toString(16).padStart(4, '0')}`;

/** An account with one vault, one lockbox and the secrets it was given. */
async function seed(
    crypto: CryptoClient,
    secrets: Array<{ uuid: string; payload: SecretPayload }>,
    files: FileRecord[] = [],
): Promise<ExportBundle> {
    const registration = await crypto.register({
        password: 'correct horse battery staple',
        kdfSalt: new Uint8Array(16),
        kdfParams: FAST_KDF,
        uuid: USER_UUID,
    });

    await loadIdentity(crypto, USER_UUID, {
        x25519PrivateKeyCt: toBase64(registration.x25519PrivateKeyCt),
        ed25519PrivateKeyCt: toBase64(registration.ed25519PrivateKeyCt),
    });

    const sealedVault = await sealNewVault(
        crypto,
        VAULT_UUID,
        MEMBERSHIP_UUID,
        toBase64(registration.x25519PublicKey),
        { name: 'Production', description: 'live credentials' },
    );

    const vault: VaultRecord = {
        uuid: VAULT_UUID,
        payloadCt: sealedVault.payload_ct,
        wrappedItemKey: sealedVault.wrapped_item_key,
        payloadVersion: sealedVault.payload_version,
        keyEpoch: 1,
        updatedAt: null,
        history: { maxVersions: 20, maxAgeDays: 180, isDefault: true },
        rotation: { rotatedAt: null, afterDays: 0, dueAt: null, isDue: false, isDefault: true },
        membership: {
            uuid: MEMBERSHIP_UUID,
            role: 'owner',
            wrappedVaultKey: sealedVault.wrapped_vault_key,
            keyEpoch: 1,
        },
    };

    const sealedLockbox = await sealItem(crypto, VAULT_UUID, 'lockbox.payload', LOCKBOX_UUID, {
        name: 'Cloud',
        description: '',
    });

    const records: SecretRecord[] = [];

    for (const { uuid, payload } of secrets) {
        const sealed = await sealItem(crypto, VAULT_UUID, 'secret.payload', uuid, payload);

        records.push({
            uuid,
            lockboxUuid: LOCKBOX_UUID,
            payloadCt: sealed.payload_ct,
            wrappedItemKey: sealed.wrapped_item_key,
            payloadVersion: PAYLOAD_VERSION,
            version: 1,
            sortOrder: records.length,
            linkedLockboxUuid: null,
            historyCount: 0,
            updatedAt: '2026-08-17T09:00:00+00:00',
        });
    }

    return {
        handle: 'phil',
        vaults: [
            {
                vault,
                lockboxes: [
                    {
                        uuid: LOCKBOX_UUID,
                        payloadCt: sealedLockbox.payload_ct,
                        wrappedItemKey: sealedLockbox.wrapped_item_key,
                        payloadVersion: PAYLOAD_VERSION,
                        sortOrder: 0,
                        secretCount: records.length,
                        updatedAt: null,
                    } satisfies LockboxRecord,
                ],
                secrets: records,
                files,
            },
        ],
    };
}

const password = (key: string, value: string): SecretPayload => ({
    type: 'password',
    key,
    value,
    notes: '',
});

describe('runExport', () => {
    it('decrypts every vault, lockbox and secret in the account', async () => {
        const crypto = client();
        const bundle = await seed(crypto, [
            { uuid: uuidAt(1), payload: password('AWS root', 'hunter2') },
            { uuid: uuidAt(2), payload: password('Cloudflare', 'token') },
        ]);

        const document = await runExport({ client: crypto, bundle, includeFiles: true });

        expect(document.format).toBe(EXPORT_FORMAT);
        expect(document.account.handle).toBe('phil');
        expect(document.vaults[0]?.payload?.name).toBe('Production');
        expect(document.vaults[0]?.lockboxes[0]?.payload?.name).toBe('Cloud');
        expect(document.vaults[0]?.lockboxes[0]?.secrets.map((s) => s.payload?.key)).toEqual([
            'AWS root',
            'Cloudflare',
        ]);
    });

    /*
     | The rule this module exists to keep. A payload written by a later build
     | carries keys this one has never heard of, and an export that reassembled
     | it from the fields it recognises would drop them — in the one file that
     | might be the only remaining copy.
     */
    it('copies the payload verbatim, including keys this build does not know', async () => {
        const crypto = client();
        const bundle = await seed(crypto, [
            {
                uuid: uuidAt(1),
                payload: {
                    ...password('Router', 'admin'),
                    quantumResistantThing: 'from a later build',
                } as SecretPayload,
            },
        ]);

        const secret = (await runExport({ client: crypto, bundle, includeFiles: true })).vaults[0]
            ?.lockboxes[0]?.secrets[0];

        expect(secret?.payload).toMatchObject({
            type: 'password',
            key: 'Router',
            value: 'admin',
            quantumResistantThing: 'from a later build',
        });
    });

    it('reports an unreadable secret rather than dropping it', async () => {
        const crypto = client();
        const bundle = await seed(crypto, [
            { uuid: uuidAt(1), payload: password('Good', 'fine') },
            { uuid: uuidAt(2), payload: password('Damaged', 'gone') },
        ]);

        const secrets = bundle.vaults[0]!.secrets;
        secrets[1]!.payloadCt = tamper(secrets[1]!.payloadCt);

        const exported = (await runExport({ client: crypto, bundle, includeFiles: true })).vaults[0]
            ?.lockboxes[0]?.secrets;

        // Both are present. The damaged one carries an error where its payload
        // would be, which is SR3 applied to the file rather than to a page.
        expect(exported).toHaveLength(2);
        expect(exported?.[0]?.payload?.key).toBe('Good');
        expect(exported?.[1]?.payload).toBeNull();
        expect(exported?.[1]?.error).toContain('This secret');
    });

    it('records a vault it could not open, and does not pretend it was empty', async () => {
        const crypto = client();
        const bundle = await seed(crypto, [{ uuid: uuidAt(1), payload: password('AWS', 'x') }]);

        bundle.vaults[0]!.vault.payloadCt = tamper(bundle.vaults[0]!.vault.payloadCt);

        const vault = (await runExport({ client: crypto, bundle, includeFiles: true })).vaults[0];

        expect(vault?.payload).toBeNull();
        expect(vault?.error).toContain('This vault');
        // Nothing below it is claimed to have been read.
        expect(vault?.lockboxes).toEqual([]);
    });

    it('marks a vault somebody else owns, so the reader knows whose data it is', async () => {
        const crypto = client();
        const bundle = await seed(crypto, []);
        bundle.vaults[0]!.vault.membership.role = 'viewer';

        const vault = (await runExport({ client: crypto, bundle, includeFiles: true })).vaults[0];

        expect(vault?.shared).toBe(true);
        expect(vault?.role).toBe('viewer');
    });

    it('reports progress across everything it has to open', async () => {
        const crypto = client();
        const bundle = await seed(crypto, [
            { uuid: uuidAt(1), payload: password('One', '1') },
            { uuid: uuidAt(2), payload: password('Two', '2') },
        ]);

        const seen: Array<[number, number]> = [];
        await runExport({
            client: crypto,
            bundle,
            includeFiles: true,
            onProgress: (done, total) => seen.push([done, total]),
        });

        // One vault, one lockbox, two secrets.
        expect(seen.at(-1)).toEqual([4, 4]);
    });

    it('says so in the document when attachments were left out on purpose', async () => {
        const crypto = client();
        const document = await runExport({
            client: crypto,
            bundle: await seed(crypto, []),
            includeFiles: false,
        });

        expect(document.omissions[0]).toContain('Attachment contents');
    });

    it('does not try to fetch the body of an upload that never finished', async () => {
        const crypto = client();
        const manifest: FileManifest = {
            filename: 'id_ed25519',
            mime: 'text/plain',
            sha256: 'f'.repeat(64),
            chunkCount: 1,
            chunkSize: 1024,
            plaintextSize: 464,
            noncePrefix: toBase64(new Uint8Array(8)),
        };

        const bundle = await seed(crypto, []);
        const sealed = await sealItem(crypto, VAULT_UUID, 'file.payload', FILE_UUID, manifest);

        bundle.vaults[0]!.files = [
            {
                uuid: FILE_UUID,
                lockboxUuid: LOCKBOX_UUID,
                payloadCt: sealed.payload_ct,
                wrappedItemKey: sealed.wrapped_item_key,
                payloadVersion: PAYLOAD_VERSION,
                chunkCount: 1,
                ciphertextSize: 0,
                uploadedAt: null,
                sortOrder: 0,
                updatedAt: null,
            },
        ];

        const file = (await runExport({ client: crypto, bundle, includeFiles: true })).vaults[0]?.lockboxes[0]
            ?.files[0];

        // Named, described and hashed. Only the body is missing, and it says why
        // — there is no complete copy on the server to take.
        expect(file?.filename).toBe('id_ed25519');
        expect(file?.bytes).toBe(464);
        expect(file?.body).toBeNull();
        expect(file?.omitted).toContain('never finished');
    });
});

describe('planInlineFiles', () => {
    const candidate = (size: number, uuid = FILE_UUID) => ({
        record: { uuid } as FileRecord,
        manifest: { plaintextSize: size } as FileManifest,
        error: null,
    });

    it('inlines files while the budget lasts, in document order', () => {
        const plan = planInlineFiles([candidate(600), candidate(300), candidate(200)], 1000);

        expect(plan.map((entry) => entry.inline)).toEqual([true, true, false]);
    });

    it('takes a later file that still fits after a big one was refused', () => {
        // Deliberate: the alternative is stopping at the first refusal, which
        // would leave a small file out because an unrelated large one came
        // first.
        const plan = planInlineFiles([candidate(5000), candidate(10)], 1000);

        expect(plan.map((entry) => entry.inline)).toEqual([false, true]);
    });

    it('explains a refusal with both numbers', () => {
        const [entry] = planInlineFiles([candidate(30 * 1024 * 1024)], INLINE_BUDGET_BYTES);

        expect(entry?.inline).toBe(false);
        expect(entry?.inline === false && entry.reason).toContain('30 MiB');
        expect(entry?.inline === false && entry.reason).toContain('25 MiB');
    });

    it('refuses a file whose manifest could not be read, and says which problem it is', () => {
        const plan = planInlineFiles(
            [{ record: { uuid: FILE_UUID } as FileRecord, manifest: null, error: 'nope' }],
            1000,
        );

        expect(plan[0]?.inline === false && plan[0].reason).toContain('manifest');
    });

    it('inlines nothing at a budget of zero', () => {
        expect(planInlineFiles([candidate(1)], 0).every((entry) => !entry.inline)).toBe(true);
    });
});

describe('the plaintext form', () => {
    const document = buildExportDocument({
        handle: 'phil',
        vaults: [],
        omissions: standardOmissions(),
        exportedAt: new Date('2026-08-17T09:30:00Z'),
    });

    it('leads with the warning, before anything else a reader might skim past', () => {
        const parsed = JSON.parse(serialisePlaintext(document)) as Record<string, unknown>;

        expect(Object.keys(parsed).indexOf('warning')).toBeLessThan(Object.keys(parsed).indexOf('vaults'));
        expect((parsed.warning as string[])[0]).toBe('THIS FILE IS NOT ENCRYPTED.');
    });

    it('says the file is not protected by the master password', () => {
        expect(PLAINTEXT_WARNING.join(' ')).toContain('not protected by your master password');
    });

    it('leaves the warning out of the archive form, which does not need it', () => {
        expect(JSON.parse(serialiseArchivePlaintext(document))).not.toHaveProperty('warning');
    });

    it('names version history as a deliberate omission with its reason', () => {
        expect(standardOmissions().join(' ')).toContain('rotated');
    });
});

describe('filenames', () => {
    it('dates itself and says which of the two files it is', () => {
        const at = new Date('2026-08-17T09:30:00Z');

        expect(exportFilename('archive', at)).toBe('vault-export-2026-08-17.vaultarchive');
        expect(exportFilename('plaintext', at)).toContain('PLAINTEXT');
    });
});

describe('encryptExport', () => {
    /*
     | The only test in the suite that runs Argon2id at the parameters an
     | archive actually ships with, and it costs about five seconds. It earns
     | that by being the one assertion that the two halves of this feature meet:
     | a document written by the export page, opened by the code the offline
     | decryptor is built from. Everything else runs at a cost nobody would ship,
     | and archive.test.ts asserts the shipped parameters separately.
     */
    it('produces an archive the decryptor can open', () => {
        const document = buildExportDocument({ handle: 'phil', vaults: [], omissions: [] });

        const archive = encryptExport(document, 'a-long-enough-passphrase');
        const opened: unknown = JSON.parse(
            new TextDecoder().decode(openArchive('a-long-enough-passphrase', archive)),
        );

        expect(opened).toEqual(document);
        // Each archive carries its own UUID, generated here rather than by a
        // caller, so no two can share an identity.
        expect(readArchiveHeader(archive).uuid).toMatch(/^[0-9a-f]{8}-/);
    }, 60_000);
});
