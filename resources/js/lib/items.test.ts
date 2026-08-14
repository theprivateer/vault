/**
 * The vault → lockbox → secret flow, end to end against a real keyring.
 *
 * These run the genuine crypto core rather than a stub, because the property
 * worth testing is that what the server would store is exactly what a fresh
 * browser can open again — and a stub would prove only that the stub agrees
 * with itself.
 */
import { describe, expect, it } from 'vitest';

import { CryptoClient } from '@/crypto/worker/client';
import { installHandler, type WorkerScope } from '@/crypto/worker/handler';
import type { Reply, Request } from '@/crypto/worker/protocol';
import { itemKeyHandle, vaultKeyHandle } from '@/crypto/worker/protocol';

import { toBase64 } from './bytes';
import {
    loadIdentity,
    openItem,
    openVaultKey,
    sealItem,
    sealNewVault,
    type LockboxPayload,
    type SecretPayload,
    type VaultPayload,
    type VaultRecord,
} from './items';

const FAST_KDF = { m: 8, t: 1, p: 1 };

const USER_UUID = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f6';
const VAULT_UUID = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f7';
const MEMBERSHIP_UUID = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f8';
const LOCKBOX_UUID = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f9';
const SECRET_UUID = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5fa';

/** Runs the real handler in-process, as the client tests do. */
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
        this.scope.onmessage?.({ data: message });
    }

    terminate(): void {}
}

function client(): CryptoClient {
    return new CryptoClient(() => new FakeWorker() as unknown as Worker);
}

/** Registers an account and loads its identity, as unlocking does. */
async function account(crypto: CryptoClient) {
    const registration = await crypto.register({
        password: 'correct horse battery staple',
        kdfSalt: new Uint8Array(16),
        kdfParams: FAST_KDF,
        uuid: USER_UUID,
    });

    await loadIdentity(crypto, USER_UUID, toBase64(registration.x25519PrivateKeyCt));

    return registration;
}

describe('creating and reopening a vault', () => {
    it('produces blobs a fresh session can open with nothing else', async () => {
        const crypto = client();
        const registration = await account(crypto);

        const payload: VaultPayload = { name: 'Production', description: 'live credentials' };

        const sealed = await sealNewVault(
            crypto,
            VAULT_UUID,
            MEMBERSHIP_UUID,
            toBase64(registration.x25519PublicKey),
            payload,
        );

        // Exactly the shape the API stores, and all of it opaque.
        const stored: VaultRecord = {
            uuid: VAULT_UUID,
            payloadCt: sealed.payload_ct,
            wrappedItemKey: sealed.wrapped_item_key,
            payloadVersion: sealed.payload_version,
            keyEpoch: 1,
            updatedAt: null,
            membership: {
                uuid: MEMBERSHIP_UUID,
                role: 'owner',
                wrappedVaultKey: sealed.wrapped_vault_key,
                keyEpoch: 1,
            },
        };

        // Drop every derived key, then rebuild from the stored blobs alone.
        await crypto.forget(vaultKeyHandle(VAULT_UUID));
        await crypto.forget(itemKeyHandle(VAULT_UUID));

        await openVaultKey(crypto, stored);

        expect(await openItem<VaultPayload>(crypto, VAULT_UUID, 'vault.payload', stored)).toEqual(payload);
    });

    it('round-trips a lockbox and a secret under the same vault key', async () => {
        const crypto = client();
        await account(crypto);

        await crypto.generateInto(vaultKeyHandle(VAULT_UUID));

        const lockbox: LockboxPayload = { name: 'Databases', description: '' };
        const secret: SecretPayload = {
            type: 'password',
            key: 'primary',
            value: 'hunter2',
            notes: '',
            paranoid: true,
        };

        const sealedLockbox = await sealItem(crypto, VAULT_UUID, 'lockbox.payload', LOCKBOX_UUID, lockbox);
        const sealedSecret = await sealItem(crypto, VAULT_UUID, 'secret.payload', SECRET_UUID, secret);

        const asStored = (uuid: string, sealed: { payload_ct: string; wrapped_item_key: string }) => ({
            uuid,
            payloadCt: sealed.payload_ct,
            wrappedItemKey: sealed.wrapped_item_key,
            payloadVersion: 1,
        });

        expect(
            await openItem<LockboxPayload>(
                crypto,
                VAULT_UUID,
                'lockbox.payload',
                asStored(LOCKBOX_UUID, sealedLockbox),
            ),
        ).toEqual(lockbox);

        expect(
            await openItem<SecretPayload>(
                crypto,
                VAULT_UUID,
                'secret.payload',
                asStored(SECRET_UUID, sealedSecret),
            ),
        ).toEqual(secret);
    });

    it('gives every item its own key, so identical payloads differ', async () => {
        const crypto = client();
        await account(crypto);

        await crypto.generateInto(vaultKeyHandle(VAULT_UUID));

        const payload = { name: 'Same', description: 'Same' };

        const first = await sealItem(crypto, VAULT_UUID, 'lockbox.payload', LOCKBOX_UUID, payload);
        const second = await sealItem(crypto, VAULT_UUID, 'lockbox.payload', SECRET_UUID, payload);

        expect(first.payload_ct).not.toBe(second.payload_ct);
        expect(first.wrapped_item_key).not.toBe(second.wrapped_item_key);
    });

    /*
     | Re-encrypting under a fresh key on every write is what stops a rotated
     | password staying readable to anyone who captured the old item key.
     */
    it('re-keys an item on update rather than reusing its key', async () => {
        const crypto = client();
        await account(crypto);

        await crypto.generateInto(vaultKeyHandle(VAULT_UUID));

        const before = await sealItem(crypto, VAULT_UUID, 'secret.payload', SECRET_UUID, {
            value: 'old',
        });
        const after = await sealItem(crypto, VAULT_UUID, 'secret.payload', SECRET_UUID, {
            value: 'new',
        });

        expect(before.wrapped_item_key).not.toBe(after.wrapped_item_key);
    });
});

describe('associated data binding', () => {
    /*
     | SR4, from the application's side rather than the crypto core's. A server
     | that served one record's ciphertext in another record's place has to
     | produce an error, not a plausible-looking secret.
     */
    it("refuses a payload served under a different record's identifier", async () => {
        const crypto = client();
        await account(crypto);

        await crypto.generateInto(vaultKeyHandle(VAULT_UUID));

        const sealed = await sealItem(crypto, VAULT_UUID, 'secret.payload', SECRET_UUID, {
            value: 'hunter2',
        });

        await expect(
            openItem(crypto, VAULT_UUID, 'secret.payload', {
                // The same bytes, presented as a different secret.
                uuid: LOCKBOX_UUID,
                payloadCt: sealed.payload_ct,
                wrappedItemKey: sealed.wrapped_item_key,
                payloadVersion: 1,
            }),
        ).rejects.toThrow();
    });

    it('refuses a lockbox payload presented as a secret', async () => {
        const crypto = client();
        await account(crypto);

        await crypto.generateInto(vaultKeyHandle(VAULT_UUID));

        const sealed = await sealItem(crypto, VAULT_UUID, 'lockbox.payload', LOCKBOX_UUID, {
            name: 'Databases',
        });

        await expect(
            openItem(crypto, VAULT_UUID, 'secret.payload', {
                uuid: LOCKBOX_UUID,
                payloadCt: sealed.payload_ct,
                wrappedItemKey: sealed.wrapped_item_key,
                payloadVersion: 1,
            }),
        ).rejects.toThrow();
    });

    it('refuses a vault key sealed for a different membership row', async () => {
        const crypto = client();
        const registration = await account(crypto);

        const sealed = await sealNewVault(
            crypto,
            VAULT_UUID,
            MEMBERSHIP_UUID,
            toBase64(registration.x25519PublicKey),
            { name: 'Production', description: '' },
        );

        await expect(
            openVaultKey(crypto, {
                uuid: VAULT_UUID,
                payloadCt: sealed.payload_ct,
                wrappedItemKey: sealed.wrapped_item_key,
                payloadVersion: 1,
                keyEpoch: 1,
                updatedAt: null,
                membership: {
                    // Someone else's row, carrying this key.
                    uuid: LOCKBOX_UUID,
                    role: 'owner',
                    wrappedVaultKey: sealed.wrapped_vault_key,
                    keyEpoch: 1,
                },
            }),
        ).rejects.toThrow();
    });
});
