/**
 * Archiving a superseded payload, against the real crypto core.
 *
 * The property under test is the one the whole design turns on: **an archived
 * version is bound to its own identity and its own context, so it can never be
 * mistaken for the live payload.** If it could, a server holding both could
 * write any old version back over the current row and every client would verify
 * it happily — a silent rollback to a password that was rotated because it
 * leaked, which is exactly the attack that adding history creates.
 *
 * A stub would prove only that the stub agrees with itself, so these run the
 * genuine handler and the genuine keyring.
 */
import { describe, expect, it } from 'vitest';

import { CryptoClient, isIntegrityFailure } from '@/crypto/worker/client';
import { installHandler, type WorkerScope } from '@/crypto/worker/handler';
import type { Reply, Request } from '@/crypto/worker/protocol';
import { vaultKeyHandle } from '@/crypto/worker/protocol';

import { comparePayloads, openVersions, sealVersion, type VersionRecord } from './history';
import { openItem, type SecretPayload } from './items';
import { ALL_FIELD_KEYS } from './secretTypes';

const VAULT_UUID = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f7';
const SECRET_UUID = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5fa';

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

/** A client holding a vault key, which is all archiving needs. */
async function vaultClient(): Promise<CryptoClient> {
    const crypto = new CryptoClient(() => new FakeWorker() as unknown as Worker);

    await crypto.generateInto(vaultKeyHandle(VAULT_UUID));

    return crypto;
}

function payload(overrides: Partial<SecretPayload> = {}): SecretPayload {
    return {
        type: 'password',
        key: 'Router',
        value: 'hunter2',
        notes: 'upstairs',
        ...overrides,
    };
}

function record(sealed: Awaited<ReturnType<typeof sealVersion>>, version = 1): VersionRecord {
    return {
        uuid: sealed.version_uuid,
        payloadCt: sealed.version_payload_ct,
        wrappedItemKey: sealed.version_wrapped_item_key,
        payloadVersion: sealed.version_payload_version,
        version,
        author: 'Phil',
        createdAt: '2026-08-16T09:00:00Z',
    };
}

describe('archiving a superseded payload', () => {
    it('round-trips through a session that holds only the vault key', async () => {
        const crypto = await vaultClient();
        const before = payload();

        const sealed = await sealVersion(crypto, VAULT_UUID, before);
        const [opened] = await openVersions(crypto, VAULT_UUID, [record(sealed)]);

        expect(opened?.error).toBeNull();
        expect(opened?.payload).toEqual(before);
    });

    it('gives every archive a fresh identity and a fresh key', async () => {
        const crypto = await vaultClient();

        const first = await sealVersion(crypto, VAULT_UUID, payload());
        const second = await sealVersion(crypto, VAULT_UUID, payload());

        expect(first.version_uuid).not.toBe(second.version_uuid);
        expect(first.version_wrapped_item_key).not.toBe(second.version_wrapped_item_key);
        // Same plaintext, different key: identical ciphertext would mean the
        // key was reused, and a server could then tell that nothing changed.
        expect(first.version_payload_ct).not.toBe(second.version_payload_ct);
    });

    /*
     | The attack this design exists to prevent, run as a test.
     |
     | A server that copied an archived version's ciphertext into
     | `secrets.payload_ct` would be offering an old password as the current
     | one. It fails because the archive was sealed under
     | `secret.version.payload` at its own UUID, and the live column is read
     | with `secret.payload` at the secret's UUID — two different bindings, so
     | the tag does not verify.
     */
    it('refuses to open an archived payload as if it were the live one', async () => {
        const crypto = await vaultClient();

        const sealed = await sealVersion(crypto, VAULT_UUID, payload());

        const substituted = {
            uuid: SECRET_UUID,
            payloadCt: sealed.version_payload_ct,
            wrappedItemKey: sealed.version_wrapped_item_key,
            payloadVersion: sealed.version_payload_version,
        };

        /*
         | `isIntegrityFailure` rather than `instanceof`: the error crossed the
         | Worker boundary and was rebuilt from its serialised form on this
         | side, so the identity check that matters is the one the application
         | itself uses.
         */
        await expect(
            openItem<SecretPayload>(crypto, VAULT_UUID, 'secret.payload', substituted),
        ).rejects.toSatisfy(isIntegrityFailure);
    });

    /*
     | And the same substitution in the other direction: an archive served under
     | a different version row's identity. Binding to the row's own UUID is what
     | stops a server reordering a history or presenting version 2 as version 7.
     */
    it('refuses an archive served under another version’s identity', async () => {
        const crypto = await vaultClient();

        const mine = await sealVersion(crypto, VAULT_UUID, payload());
        const theirs = await sealVersion(crypto, VAULT_UUID, payload({ value: 'other' }));

        const [opened] = await openVersions(crypto, VAULT_UUID, [
            { ...record(mine), payloadCt: theirs.version_payload_ct },
        ]);

        expect(opened?.payload).toBeNull();
        expect(opened?.error).toContain('could not be verified');
    });

    /*
     | A failure stays attached to the entry that failed. One unreadable version
     | must not blank the ten around it — and it must not render as an empty
     | version either, which was the 2017 bug this project exists to fix.
     */
    it('isolates an unreadable version from the ones beside it', async () => {
        const crypto = await vaultClient();

        const good = await sealVersion(crypto, VAULT_UUID, payload());
        const corrupt = await sealVersion(crypto, VAULT_UUID, payload({ value: 'gone' }));

        const opened = await openVersions(crypto, VAULT_UUID, [
            record(good, 2),
            { ...record(corrupt, 1), payloadCt: `${corrupt.version_payload_ct.slice(0, -4)}AAAA` },
        ]);

        expect(opened[0]?.payload).toEqual(payload());
        expect(opened[1]?.payload).toBeNull();
        expect(opened[1]?.error).toContain('Version 1');
    });
});

describe('comparing two versions', () => {
    it('names the fields that moved and leaves the rest alone', () => {
        const diffs = comparePayloads(
            payload({ value: 'hunter2', notes: 'upstairs' }),
            payload({ value: 'correct-horse', notes: 'upstairs' }),
        );

        const changed = diffs.filter((field) => field.changed).map((field) => field.field);

        expect(changed).toEqual(['value']);
        expect(diffs.find((field) => field.field === 'notes')?.ops).toEqual([]);
    });

    it('treats an absent optional field as an empty one rather than undefined', () => {
        const diffs = comparePayloads(payload(), payload({ url: 'https://example.test' }));

        const url = diffs.find((field) => field.field === 'url');

        expect(url?.changed).toBe(true);
        expect(url?.ops.map((op) => op.text)).toEqual(['', 'https://example.test']);
    });

    /*
     | A fixed field list, not the union of both objects' keys. A payload from a
     | future build could carry a field this one knows nothing about, and
     | rendering an unknown key's contents into the page unlabelled is how a
     | diff view becomes the place an unexpected value gets displayed.
     */
    it('ignores fields it does not know about', () => {
        const surprise = { ...payload(), secretQuestion: 'mother’s maiden name' } as SecretPayload;

        const fields = comparePayloads(payload(), surprise).map((field) => field.field);

        expect(fields).not.toContain('secretQuestion');

        /*
         | Asserted as a closed set rather than as a literal list. The list grows
         | whenever a type declares a new field, and a test pinned to a snapshot
         | of it fails on every such change while saying nothing about the
         | property that matters — which is that the set is closed at all, and
         | that `secretQuestion` is outside it.
         */
        expect(new Set(fields)).toEqual(new Set(['key', 'type', ...ALL_FIELD_KEYS]));
    });
});
