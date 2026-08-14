/**
 * Turning vault records into plaintext, and plaintext back into records.
 *
 * This is the one module that knows how a vault, a lockbox and a secret map on
 * to the key hierarchy. Everything above it deals in decrypted objects and
 * everything below it deals in bytes inside the Worker.
 *
 * **The client builds every AAD itself, from the UUID of the record it is
 * holding.** The server never supplies associated data, and must not: a
 * malicious server that could name the AAD could hand over one record's
 * ciphertext with instructions to verify it against another, which is exactly
 * the substitution the binding exists to detect (SR4).
 */
import type { AadContext, AadParams } from '@/crypto/aad';
import type { CryptoClient } from '@/crypto/worker/client';
import { USER_KEY, X25519_KEY, itemKeyHandle, vaultKeyHandle } from '@/crypto/worker/protocol';

import { decodeUtf8, encodeUtf8, fromBase64, toBase64 } from './bytes';

/** The schema version of the JSON inside a payload. Bound into its AAD. */
export const PAYLOAD_VERSION = 1;

/**
 * Key wrappings carry their own version, fixed at 1.
 *
 * A wrapped key has no schema to evolve — it is 32 bytes — so tying its AAD to
 * the payload version would make an item key's binding change every time an
 * unrelated field was added to the JSON beside it.
 */
const KEY_WRAP_VERSION = 1;

export type SecretType = 'password' | 'note' | 'key' | 'card' | 'lockbox';

export interface VaultPayload {
    name: string;
    description: string;
}

export interface LockboxPayload {
    name: string;
    description: string;
}

export interface SecretPayload {
    /**
     * Inside the payload, never a column: a type column would tell the server
     * which rows are SSH keys and which are notes, for free.
     */
    type: SecretType;
    key: string;
    value: string;
    notes: string;
    url?: string;
    /**
     * The 2017 `paranoid` flag, demoted from a column to a UI hint: require a
     * deliberate action to reveal, never copy automatically. It was never a
     * security control and is not one here.
     */
    paranoid?: boolean;
}

/** The stored shape of anything with a payload. */
export interface EncryptedItem {
    uuid: string;
    payloadCt: string;
    wrappedItemKey: string;
    payloadVersion: number;
}

export interface VaultRecord extends EncryptedItem {
    keyEpoch: number;
    updatedAt: string | null;
    membership: {
        uuid: string;
        role: 'owner' | 'editor' | 'viewer';
        wrappedVaultKey: string;
        keyEpoch: number;
    };
}

export interface LockboxRecord extends EncryptedItem {
    sortOrder: number;
    secretCount: number;
    updatedAt: string | null;
}

export interface SecretRecord extends EncryptedItem {
    sortOrder: number;
    linkedLockboxUuid: string | null;
    updatedAt: string | null;
}

/** What a create or update posts back: a new key and a fresh ciphertext. */
export interface SealedPayload {
    payload_ct: string;
    wrapped_item_key: string;
    payload_version: number;
}

function aad(context: AadContext, subject: string, version: number): AadParams {
    return { context, subject, version };
}

/**
 * Loads the identity private keys into the Worker.
 *
 * Called as part of unlocking, so "unlocked" always means the browser can open
 * a sealed vault key — rather than a second state where the User Key is present
 * but nothing can actually be read.
 */
export async function loadIdentity(
    client: CryptoClient,
    userUuid: string,
    x25519PrivateKeyCt: string,
): Promise<void> {
    await client.unwrapInto({
        handle: X25519_KEY,
        using: USER_KEY,
        wrapped: fromBase64(x25519PrivateKeyCt),
        aad: aad('user.privkey.x25519', userUuid, KEY_WRAP_VERSION),
    });
}

/**
 * Unwraps a vault's key from the membership row and holds it in the Worker.
 *
 * The AAD binds to the *membership* UUID, not the vault's: that is what stops a
 * server moving one member's sealed key onto another member's row.
 */
export async function openVaultKey(client: CryptoClient, vault: VaultRecord): Promise<void> {
    await client.openSealedInto({
        handle: vaultKeyHandle(vault.uuid),
        using: X25519_KEY,
        sealed: fromBase64(vault.membership.wrappedVaultKey),
        aad: aad('vault.membership.key', vault.membership.uuid, KEY_WRAP_VERSION),
    });
}

/**
 * Decrypts one item under a vault key already held.
 *
 * Throws on any failure, and the caller must show that failure rather than an
 * empty field. Returning null here would recreate the 2017 bug this whole
 * project exists to correct (SR3).
 */
export async function openItem<T>(
    client: CryptoClient,
    vaultUuid: string,
    context: AadContext,
    item: EncryptedItem,
): Promise<T> {
    const handle = itemKeyHandle(item.uuid);

    await client.unwrapInto({
        handle,
        using: vaultKeyHandle(vaultUuid),
        wrapped: fromBase64(item.wrappedItemKey),
        aad: aad('item.key', item.uuid, KEY_WRAP_VERSION),
    });

    const plaintext = await client.open(
        handle,
        fromBase64(item.payloadCt),
        aad(context, item.uuid, item.payloadVersion),
    );

    return JSON.parse(decodeUtf8(plaintext)) as T;
}

/**
 * Encrypts an item under a fresh Item Key.
 *
 * A new key every time, on create and on update alike. Re-using an item key
 * across two versions of a payload would encrypt two plaintexts under one key,
 * and would leave a rotated secret readable by anyone who had captured the old
 * key.
 */
export async function sealItem(
    client: CryptoClient,
    vaultUuid: string,
    context: AadContext,
    uuid: string,
    payload: unknown,
): Promise<SealedPayload> {
    const handle = itemKeyHandle(uuid);

    await client.generateInto(handle);

    const payloadCt = await client.seal(
        handle,
        encodeUtf8(JSON.stringify(payload)),
        aad(context, uuid, PAYLOAD_VERSION),
    );

    const wrappedItemKey = await client.wrapFrom(
        handle,
        vaultKeyHandle(vaultUuid),
        aad('item.key', uuid, KEY_WRAP_VERSION),
    );

    return {
        payload_ct: toBase64(payloadCt),
        wrapped_item_key: toBase64(wrappedItemKey),
        payload_version: PAYLOAD_VERSION,
    };
}

/** Everything a new vault posts: its payload, and the key sealed to its owner. */
export interface SealedVault extends SealedPayload {
    uuid: string;
    membership_uuid: string;
    wrapped_vault_key: string;
}

/**
 * Creates a whole vault client-side.
 *
 * The Vault Key is generated here and sealed to the creator's own public key.
 * The server receives one sealed box and never sees the key inside it — which
 * is why a vault must be created together with its membership row, since that
 * row is the only place the key exists at all.
 */
export async function sealNewVault(
    client: CryptoClient,
    uuid: string,
    membershipUuid: string,
    ownPublicKey: string,
    payload: VaultPayload,
): Promise<SealedVault> {
    await client.generateInto(vaultKeyHandle(uuid));

    const sealed = await sealItem(client, uuid, 'vault.payload', uuid, payload);

    const wrappedVaultKey = await client.sealToPublicKey(
        vaultKeyHandle(uuid),
        fromBase64(ownPublicKey),
        aad('vault.membership.key', membershipUuid, KEY_WRAP_VERSION),
    );

    return {
        ...sealed,
        uuid,
        membership_uuid: membershipUuid,
        wrapped_vault_key: toBase64(wrappedVaultKey),
    };
}
