/**
 * The store that holds plaintext, and the three things it must never get wrong.
 *
 * Everything else in the application handles ciphertext; this is the one place
 * decrypted secrets sit around waiting to be rendered. The tests are shaped
 * around lifetime rather than around features, because a store that is merely
 * *slow* is a bug and a store that is still full after a lock is a disclosure.
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { CryptoClient } from '@/crypto/worker/client';
import { installHandler, type WorkerScope } from '@/crypto/worker/handler';
import type { Reply, Request } from '@/crypto/worker/protocol';
import { fromBase64, toBase64 } from '@/lib/bytes';
import {
    loadIdentity,
    PAYLOAD_VERSION,
    sealItem,
    sealNewVault,
    type LockboxRecord,
    type SecretPayload,
    type SecretRecord,
    type VaultRecord,
} from '@/lib/items';

import { lock, markAuthenticated, resetSession } from './session';
import { applyOptimistic, openContents, removeOptimistic, useVaultContents, wipe } from './vault';

const USER_UUID = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f6';
const VAULT_UUID = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f7';
const MEMBERSHIP_UUID = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f8';
const LOCKBOX_UUID = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f9';
const OTHER_VAULT_UUID = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5fb';

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

/** A vault, its lockbox and some secrets, exactly as the server would send them. */
async function seedVault(
    crypto: CryptoClient,
    secrets: Array<{ uuid: string; payload: SecretPayload }>,
    vaultUuid = VAULT_UUID,
) {
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
        vaultUuid,
        MEMBERSHIP_UUID,
        toBase64(registration.x25519PublicKey),
        { name: 'Production', description: 'live credentials' },
    );

    const vault: VaultRecord = {
        uuid: vaultUuid,
        payloadCt: sealedVault.payload_ct,
        wrappedItemKey: sealedVault.wrapped_item_key,
        payloadVersion: sealedVault.payload_version,
        keyEpoch: 1,
        updatedAt: null,
        membership: {
            uuid: MEMBERSHIP_UUID,
            role: 'owner',
            wrappedVaultKey: sealedVault.wrapped_vault_key,
            keyEpoch: 1,
        },
    };

    const sealedLockbox = await sealItem(crypto, vaultUuid, 'lockbox.payload', LOCKBOX_UUID, {
        name: 'Cloud',
        description: '',
    });

    const lockboxes: LockboxRecord[] = [
        {
            uuid: LOCKBOX_UUID,
            payloadCt: sealedLockbox.payload_ct,
            wrappedItemKey: sealedLockbox.wrapped_item_key,
            payloadVersion: PAYLOAD_VERSION,
            sortOrder: 0,
            secretCount: secrets.length,
            updatedAt: null,
        },
    ];

    const records: SecretRecord[] = [];

    for (const { uuid, payload } of secrets) {
        const sealed = await sealItem(crypto, vaultUuid, 'secret.payload', uuid, payload);

        records.push({
            uuid,
            lockboxUuid: LOCKBOX_UUID,
            payloadCt: sealed.payload_ct,
            wrappedItemKey: sealed.wrapped_item_key,
            payloadVersion: PAYLOAD_VERSION,
            version: 1,
            sortOrder: records.length,
            linkedLockboxUuid: null,
            updatedAt: null,
        });
    }

    return { vault, lockboxes, secrets: records };
}

const secret = (key: string, value: string, notes = ''): SecretPayload => ({
    type: 'password',
    key,
    value,
    notes,
});

const uuidAt = (n: number) => `0192f3a1-4b2c-7d3e-8f90-a1b2c3d4${n.toString(16).padStart(4, '0')}`;

beforeEach(() => {
    markAuthenticated();
});

afterEach(() => {
    resetSession();
    wipe();
});

describe('opening a vault', () => {
    it('decrypts every lockbox and secret in it', async () => {
        const crypto = client();
        const source = await seedVault(crypto, [
            { uuid: uuidAt(1), payload: secret('AWS root', 'hunter2') },
            { uuid: uuidAt(2), payload: secret('Cloudflare', 'token') },
        ]);

        await openContents(crypto, source);

        const { contents } = useVaultContents();

        expect(contents.value.vault?.payload?.name).toBe('Production');
        expect(contents.value.lockboxes[0]?.payload?.name).toBe('Cloud');
        expect(contents.value.secrets.map((entry) => entry.payload?.key)).toEqual(['AWS root', 'Cloudflare']);
    });

    it('reports progress ending at the total', async () => {
        const crypto = client();
        const source = await seedVault(crypto, [
            { uuid: uuidAt(1), payload: secret('one', 'a') },
            { uuid: uuidAt(2), payload: secret('two', 'b') },
        ]);

        await openContents(crypto, source);

        const { progress } = useVaultContents();

        expect(progress.value).toEqual({ done: 3, total: 3 });
    });

    /**
     * Without the Vault Key nothing beneath it is readable, so this has to be
     * a page-level failure. Rendering it as "no lockboxes" would be the 2017
     * bug in a new costume (SR3).
     */
    it('reports an unopenable vault key as a failure rather than an empty vault', async () => {
        const crypto = client();
        const source = await seedVault(crypto, [{ uuid: uuidAt(1), payload: secret('one', 'a') }]);

        // A membership row carrying the key, relabelled as someone else's.
        source.vault.membership.uuid = LOCKBOX_UUID;

        await openContents(crypto, source);

        const { failure, contents } = useVaultContents();

        expect(failure.value).not.toBe('');
        expect(contents.value.secrets).toEqual([]);
    });

    it('isolates one unreadable secret from the rest', async () => {
        const crypto = client();
        const source = await seedVault(crypto, [
            { uuid: uuidAt(1), payload: secret('good', 'a') },
            { uuid: uuidAt(2), payload: secret('bad', 'b') },
        ]);

        // One flipped bit, as a hostile or failing store would produce.
        const bytes = fromBase64(source.secrets[1]!.payloadCt);
        bytes[bytes.length - 1]! ^= 0x01;
        source.secrets[1]!.payloadCt = toBase64(bytes);

        await openContents(crypto, source);

        const { contents } = useVaultContents();

        expect(contents.value.secrets[0]?.payload?.key).toBe('good');
        expect(contents.value.secrets[1]?.payload).toBeNull();
        expect(contents.value.secrets[1]?.error).toContain('This secret');
    });
});

describe('wiping', () => {
    it('empties on lock, synchronously', async () => {
        const crypto = client();
        const source = await seedVault(crypto, [{ uuid: uuidAt(1), payload: secret('AWS', 'hunter2') }]);

        await openContents(crypto, source);

        const { contents, find } = useVaultContents();
        expect(contents.value.secrets).toHaveLength(1);

        lock('manual');

        // No await, no nextTick: the assertion is that it is already gone.
        expect(contents.value.secrets).toEqual([]);
        expect(contents.value.lockboxes).toEqual([]);
        expect(contents.value.vault).toBeNull();
        expect(find('aws')).toEqual([]);
    });

    /**
     * The race that a naive store loses: a decrypt already in flight when the
     * lock happens resolves afterwards, and writing its results in would
     * repopulate a store that is meant to be empty.
     */
    it('discards results from a decrypt that was in flight when the vault locked', async () => {
        const crypto = client();
        const source = await seedVault(crypto, [{ uuid: uuidAt(1), payload: secret('AWS', 'hunter2') }]);

        const opening = openContents(crypto, source);

        lock('manual');

        await opening;

        const { contents, busy } = useVaultContents();

        expect(contents.value.secrets).toEqual([]);
        expect(busy.value).toBe(false);
    });

    it('drops the previous vault before opening a different one', async () => {
        const crypto = client();
        const first = await seedVault(crypto, [{ uuid: uuidAt(1), payload: secret('AWS', 'hunter2') }]);

        await openContents(crypto, first);

        // A different vault, with its own key, opened over the top.
        const other = client();
        const second = await seedVault(
            other,
            [{ uuid: uuidAt(2), payload: secret('Stripe', 'sk_live') }],
            OTHER_VAULT_UUID,
        );

        await openContents(other, second);

        const { contents, find } = useVaultContents();

        expect(contents.value.secrets.map((entry) => entry.payload?.key)).toEqual(['Stripe']);
        expect(find('aws')).toEqual([]);
    });
});

describe('reusing what has already been decrypted', () => {
    it('does not need the worker again when nothing changed', async () => {
        const crypto = client();
        const source = await seedVault(crypto, [{ uuid: uuidAt(1), payload: secret('AWS', 'hunter2') }]);

        await openContents(crypto, source);

        // The vault key is still held, but every item key was forgotten after
        // use — so a second open that hit the worker would have to unwrap
        // again. What is asserted is the result, which must be identical.
        await openContents(crypto, source);

        const { contents } = useVaultContents();

        expect(contents.value.secrets.map((entry) => entry.payload?.key)).toEqual(['AWS']);
    });

    it('re-decrypts an item whose ciphertext changed', async () => {
        const crypto = client();
        const source = await seedVault(crypto, [{ uuid: uuidAt(1), payload: secret('AWS', 'hunter2') }]);

        await openContents(crypto, source);

        const rotated = await sealItem(crypto, VAULT_UUID, 'secret.payload', uuidAt(1), {
            ...secret('AWS', 'hunter3'),
        });

        await openContents(crypto, {
            ...source,
            secrets: [
                {
                    ...source.secrets[0]!,
                    payloadCt: rotated.payload_ct,
                    wrappedItemKey: rotated.wrapped_item_key,
                },
            ],
        });

        const { contents } = useVaultContents();

        expect(contents.value.secrets[0]?.payload?.value).toBe('hunter3');
    });
});

describe('search over decrypted contents', () => {
    it('finds a secret by name, and a lockbox by its own', async () => {
        const crypto = client();
        const source = await seedVault(crypto, [
            { uuid: uuidAt(1), payload: secret('AWS root account', 'hunter2') },
            { uuid: uuidAt(2), payload: secret('Stripe', 'sk_live', 'billing') },
        ]);

        await openContents(crypto, source);

        const { find } = useVaultContents();

        expect(find('aws').map((hit) => hit.id)).toEqual([uuidAt(1)]);
        expect(find('billing').map((hit) => hit.id)).toEqual([uuidAt(2)]);
        expect(find('cloud').map((hit) => hit.id)).toContain(LOCKBOX_UUID);
    });

    /** Nobody searches for a password by typing the password. */
    it('does not match a secret by its value', async () => {
        const crypto = client();
        const source = await seedVault(crypto, [
            { uuid: uuidAt(1), payload: secret('AWS root', 'correcthorse') },
        ]);

        await openContents(crypto, source);

        expect(useVaultContents().find('correcthorse')).toEqual([]);
    });

    it('finds a secret by the lockbox it sits in', async () => {
        const crypto = client();
        const source = await seedVault(crypto, [{ uuid: uuidAt(1), payload: secret('AWS root', 'x') }]);

        await openContents(crypto, source);

        expect(
            useVaultContents()
                .find('cloud aws')
                .map((hit) => hit.id),
        ).toEqual([uuidAt(1)]);
    });
});

describe('optimistic writes', () => {
    async function opened() {
        const crypto = client();
        const source = await seedVault(crypto, [{ uuid: uuidAt(1), payload: secret('AWS', 'hunter2') }]);

        await openContents(crypto, source);

        return { crypto, source };
    }

    const draft = (uuid: string): SecretRecord => ({
        uuid,
        lockboxUuid: LOCKBOX_UUID,
        payloadCt: '',
        wrappedItemKey: '',
        payloadVersion: PAYLOAD_VERSION,
        version: 1,
        sortOrder: 9,
        linkedLockboxUuid: null,
        updatedAt: null,
    });

    it('shows a new secret before the server has confirmed it', async () => {
        await opened();

        applyOptimistic({ record: draft(uuidAt(5)), payload: secret('Stripe', 'sk'), error: null });

        const { contents, find } = useVaultContents();

        expect(contents.value.secrets.map((entry) => entry.payload?.key)).toEqual(['AWS', 'Stripe']);
        // Searchable straight away, which is the point of doing it at all.
        expect(find('stripe').map((hit) => hit.id)).toEqual([uuidAt(5)]);
    });

    it('rolls a new secret back exactly', async () => {
        await opened();

        const undo = applyOptimistic({
            record: draft(uuidAt(5)),
            payload: secret('Stripe', 'sk'),
            error: null,
        });

        undo();

        const { contents, find } = useVaultContents();

        expect(contents.value.secrets.map((entry) => entry.payload?.key)).toEqual(['AWS']);
        expect(find('stripe')).toEqual([]);
    });

    it('rolls an edit back to the previous plaintext', async () => {
        await opened();

        const undo = applyOptimistic({
            record: draft(uuidAt(1)),
            payload: secret('AWS', 'hunter3'),
            error: null,
        });

        expect(useVaultContents().contents.value.secrets[0]?.payload?.value).toBe('hunter3');

        undo();

        expect(useVaultContents().contents.value.secrets[0]?.payload?.value).toBe('hunter2');
    });

    it('removes and restores in place', async () => {
        const crypto = client();
        const source = await seedVault(crypto, [
            { uuid: uuidAt(1), payload: secret('AWS', 'a') },
            { uuid: uuidAt(2), payload: secret('Stripe', 'b') },
            { uuid: uuidAt(3), payload: secret('Cloudflare', 'c') },
        ]);

        await openContents(crypto, source);

        const undo = removeOptimistic(uuidAt(2));

        expect(useVaultContents().contents.value.secrets.map((entry) => entry.payload?.key)).toEqual([
            'AWS',
            'Cloudflare',
        ]);

        undo();

        // Back where it was, not appended: an undo that reorders the list is
        // as disconcerting as one that loses the row.
        expect(useVaultContents().contents.value.secrets.map((entry) => entry.payload?.key)).toEqual([
            'AWS',
            'Stripe',
            'Cloudflare',
        ]);
    });

    it('ignores a removal of something that is not there', async () => {
        await opened();

        expect(() => removeOptimistic(uuidAt(99))()).not.toThrow();
        expect(useVaultContents().contents.value.secrets).toHaveLength(1);
    });
});

describe('grouping', () => {
    it('returns only the secrets in one lockbox', async () => {
        const crypto = client();
        const source = await seedVault(crypto, [
            { uuid: uuidAt(1), payload: secret('AWS', 'a') },
            { uuid: uuidAt(2), payload: secret('Stripe', 'b') },
        ]);

        // Non-null: seeded a line above.
        source.secrets[1]!.lockboxUuid = OTHER_VAULT_UUID;

        await openContents(crypto, source);

        expect(
            useVaultContents()
                .secretsIn(LOCKBOX_UUID)
                .map((entry) => entry.payload?.key),
        ).toEqual(['AWS']);
    });
});
