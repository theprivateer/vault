/**
 * The rule under test: a decryption failure is a state, never an absence.
 *
 * This is SR3 at the interface layer. The 2017 application returned null from
 * a failed decrypt, so a tampered secret rendered as an empty field and nobody
 * could tell. Every case here checks that a failure arrives as something the
 * interface has to display.
 */
import { describe, expect, it } from 'vitest';

import { IntegrityError, KeyUnavailableError } from '@/crypto/errors';
import { CryptoClient } from '@/crypto/worker/client';
import { installHandler, type WorkerScope } from '@/crypto/worker/handler';
import type { Reply, Request } from '@/crypto/worker/protocol';
import { vaultKeyHandle } from '@/crypto/worker/protocol';

import { describeFailure, openAll, openVault, useDecryption } from './decrypt';
import { fromBase64, toBase64 } from './bytes';
import { sealItem, type VaultRecord } from './items';

const VAULT_UUID = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f7';
const LOCKBOX_UUID = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f9';
const OTHER_UUID = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5fa';

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
        /*
         | structuredClone, exactly as a real Worker would.
         |
         | Without it this fake accepted anything — including values a real
         | postMessage refuses, such as a framework's reactive proxy. That gap
         | let a DataCloneError reach the browser with the entire suite green,
         | so the clone is the point of this method, not an incidental detail.
         */
        this.scope.onmessage?.({ data: structuredClone(message) });
    }

    terminate(): void {}
}

function client(): CryptoClient {
    return new CryptoClient(() => new FakeWorker() as unknown as Worker);
}

/** Flips one bit of a base64 envelope, as a hostile server might. */
function tamper(base64: string): string {
    const bytes = fromBase64(base64);

    // Non-null: an envelope is never empty, so the last index always exists.
    bytes[bytes.length - 1]! ^= 0x01;

    return toBase64(bytes);
}

describe('describeFailure', () => {
    it('names the record and says what an integrity failure means', () => {
        const message = describeFailure(new IntegrityError('secret.payload', VAULT_UUID), 'This secret');

        expect(message).toContain('This secret');
        expect(message).toContain('altered');
    });

    it('passes through a crypto error that already explains itself', () => {
        expect(describeFailure(new KeyUnavailableError('The vault is locked.'), 'This secret')).toBe(
            'The vault is locked.',
        );
    });

    it('still says something specific about an unrecognised failure', () => {
        expect(describeFailure(new TypeError('undefined is not a function'), 'This secret')).toBe(
            'This secret could not be decrypted.',
        );
    });
});

describe('openAll', () => {
    it('reports a tampered item as an error and never as an empty payload', async () => {
        const crypto = client();
        await crypto.generateInto(vaultKeyHandle(VAULT_UUID));

        const good = await sealItem(crypto, VAULT_UUID, 'secret.payload', LOCKBOX_UUID, { value: 'ok' });
        const bad = await sealItem(crypto, VAULT_UUID, 'secret.payload', OTHER_UUID, { value: 'gone' });

        const opened = await openAll(
            crypto,
            VAULT_UUID,
            'secret.payload',
            [
                {
                    uuid: LOCKBOX_UUID,
                    payloadCt: good.payload_ct,
                    wrappedItemKey: good.wrapped_item_key,
                    payloadVersion: 1,
                },
                {
                    uuid: OTHER_UUID,
                    payloadCt: tamper(bad.payload_ct),
                    wrappedItemKey: bad.wrapped_item_key,
                    payloadVersion: 1,
                },
            ],
            () => 'This secret',
        );

        expect(opened[0]?.payload).toEqual({ value: 'ok' });
        expect(opened[0]?.error).toBeNull();

        // The failure is loud, and the good item beside it still rendered.
        expect(opened[1]?.payload).toBeNull();
        expect(opened[1]?.error).toContain('This secret');
    });

    it('keeps the order of the records it was given', async () => {
        const crypto = client();
        await crypto.generateInto(vaultKeyHandle(VAULT_UUID));

        const first = await sealItem(crypto, VAULT_UUID, 'secret.payload', LOCKBOX_UUID, { n: 1 });
        const second = await sealItem(crypto, VAULT_UUID, 'secret.payload', OTHER_UUID, { n: 2 });

        const opened = await openAll<
            { uuid: string; payloadCt: string; wrappedItemKey: string; payloadVersion: number },
            { n: number }
        >(
            crypto,
            VAULT_UUID,
            'secret.payload',
            [
                {
                    uuid: LOCKBOX_UUID,
                    payloadCt: first.payload_ct,
                    wrappedItemKey: first.wrapped_item_key,
                    payloadVersion: 1,
                },
                {
                    uuid: OTHER_UUID,
                    payloadCt: second.payload_ct,
                    wrappedItemKey: second.wrapped_item_key,
                    payloadVersion: 1,
                },
            ],
            () => 'This secret',
        );

        expect(opened.map((entry) => entry.payload?.n)).toEqual([1, 2]);
    });
});

describe('openVault', () => {
    /*
     | Failure here is different in kind from one bad item: without the Vault
     | Key nothing beneath it can be read, so it must surface as a page-level
     | error rather than an empty list of lockboxes.
     */
    it('reports a vault whose key cannot be unsealed, rather than throwing', async () => {
        const crypto = client();

        // No identity loaded, so the sealed box cannot be opened at all.
        const record: VaultRecord = {
            uuid: VAULT_UUID,
            payloadCt: 'AQE=',
            wrappedItemKey: 'AQE=',
            payloadVersion: 1,
            keyEpoch: 1,
            updatedAt: null,
            membership: { uuid: OTHER_UUID, role: 'owner', wrappedVaultKey: 'AQE=', keyEpoch: 1 },
        };

        const opened = await openVault(crypto, record);

        expect(opened.payload).toBeNull();
        // The crypto core's own message survives, because it is more specific
        // than anything this layer could say: it names the missing key.
        expect(opened.error).toContain('identity:x25519');
    });
});

describe('useDecryption', () => {
    it('clears the busy flag and records the failure when work throws', async () => {
        const { busy, failure, run } = useDecryption();

        await run(() => Promise.reject(new IntegrityError('vault.payload', VAULT_UUID)));

        expect(busy.value).toBe(false);
        expect(failure.value).toContain('This page');
    });

    it('clears a previous failure on the next successful run', async () => {
        const { failure, run } = useDecryption();

        await run(() => Promise.reject(new Error('boom')));
        expect(failure.value).not.toBe('');

        await run(() => Promise.resolve());
        expect(failure.value).toBe('');
    });
});
