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
import { MalformedEnvelopeError } from '@/crypto/errors';
import { pad, unpad } from '@/crypto/padding';
import type { CryptoClient } from '@/crypto/worker/client';
import type { BulkOpenItem } from '@/crypto/worker/protocol';
import { ED25519_KEY, USER_KEY, X25519_KEY, itemKeyHandle, vaultKeyHandle } from '@/crypto/worker/protocol';

import { decodeUtf8, encodeUtf8, fromBase64, toBase64 } from './bytes';

/** The schema version of the JSON inside a payload. Bound into its AAD. */
export const PAYLOAD_VERSION = 2;

/**
 * The version at which payloads started being padded to bucket sizes.
 *
 * Padding is not a schema change to the JSON, but it is a change to how the
 * plaintext is framed, and there is no safe way to detect it after the fact:
 * a v1 payload run through `unpad` would either throw or, worse, silently
 * truncate a secret whose last byte happened to be `0x80`. Versioning it makes
 * the reader's decision explicit, and the version is already bound into the
 * AAD, so a server cannot relabel a v2 payload as v1 to get the old handling.
 *
 * v1 payloads are read, never written. Any item saved by this build is v2.
 */
export const PADDED_FROM_VERSION = 2;

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
     * A base32 TOTP seed, inside the payload like everything else.
     *
     * Not a column, for the same reason `type` is not: a table that said which
     * rows carry one-time-password seeds would be a list of the accounts worth
     * attacking, handed over for free.
     */
    totp?: string;
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
    /**
     * The effective retention policy, not the raw columns: a page showing
     * "null" where a number is enforced would be describing a setting rather
     * than the behaviour. `isDefault` is what lets the interface say whether
     * this vault has an opinion of its own.
     */
    history: {
        maxVersions: number;
        maxAgeDays: number;
        isDefault: boolean;
    };
    /**
     * How old this vault's key is, and whether anybody asked to be told.
     *
     * `dueAt` is null when the reminder is off, which is the default — a
     * rotation does not re-encrypt any payload, so a calendar interval bounds
     * only how long a leaked Vault Key keeps opening things written *after* the
     * leak. Worth having on purpose, not worth nagging about by default.
     */
    rotation: {
        rotatedAt: string | null;
        afterDays: number;
        dueAt: string | null;
        isDue: boolean;
        isDefault: boolean;
    };
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
    /** Which lockbox holds it — needed to group a whole vault client-side. */
    lockboxUuid: string;
    /**
     * The optimistic-concurrency token, sent back with an update. The server
     * refuses the write if it has moved on, rather than overwriting whatever
     * someone else saved in the meantime.
     */
    version: number;
    sortOrder: number;
    linkedLockboxUuid: string | null;
    /**
     * How many superseded payloads this secret has. A count, so a row can offer
     * a history link only where there is one — the versions themselves cost a
     * decrypt each and are fetched by the page that shows them.
     */
    historyCount: number;
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
 *
 * Both keys, not just X25519. The Ed25519 key signs membership grants, and an
 * unlocked session that could receive a shared vault but not share one would be
 * a distinction with no use and plenty of room for a bug.
 */
export async function loadIdentity(
    client: CryptoClient,
    userUuid: string,
    identity: { x25519PrivateKeyCt: string; ed25519PrivateKeyCt: string },
): Promise<void> {
    await client.unwrapInto({
        handle: X25519_KEY,
        using: USER_KEY,
        wrapped: fromBase64(identity.x25519PrivateKeyCt),
        aad: aad('user.privkey.x25519', userUuid, KEY_WRAP_VERSION),
    });

    await client.unwrapInto({
        handle: ED25519_KEY,
        using: USER_KEY,
        wrapped: fromBase64(identity.ed25519PrivateKeyCt),
        aad: aad('user.privkey.ed25519', userUuid, KEY_WRAP_VERSION),
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
 * Describes one item to the Worker's bulk-open operation.
 *
 * This is where the client's exclusive authorship of associated data actually
 * lives: both AADs are built here from the record's own UUID, and the server's
 * response contributes nothing but ciphertext and identifiers (SR4).
 */
export function bulkOpenItem(vaultUuid: string, context: AadContext, item: EncryptedItem): BulkOpenItem {
    return {
        using: vaultKeyHandle(vaultUuid),
        wrapped: fromBase64(item.wrappedItemKey),
        keyAad: aad('item.key', item.uuid, KEY_WRAP_VERSION),
        envelope: fromBase64(item.payloadCt),
        payloadAad: aad(context, item.uuid, item.payloadVersion),
    };
}

/**
 * Turns verified plaintext back into an object, removing padding if the
 * declared version says there is any.
 */
export function parsePayload<T>(plaintext: Uint8Array, payloadVersion: number): T {
    const json = payloadVersion >= PADDED_FROM_VERSION ? unpad(plaintext) : plaintext;

    return JSON.parse(decodeUtf8(json)) as T;
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
    const [result] = await client.openMany([bulkOpenItem(vaultUuid, context, item)]);

    if (!result) {
        throw new MalformedEnvelopeError('The worker returned no result for this item.');
    }

    if (!result.ok) {
        throw result.error;
    }

    return parsePayload<T>(result.bytes, item.payloadVersion);
}

/**
 * Encrypts an item under a fresh Item Key.
 *
 * A new key every time, on create and on update alike. Re-using an item key
 * across two versions of a payload would encrypt two plaintexts under one key,
 * and would leave a rotated secret readable by anyone who had captured the old
 * key.
 *
 * The JSON is padded to a bucket size before it is sealed, so the stored length
 * says which bucket rather than how many characters. Padding inside the AEAD
 * rather than around it means the padding is covered by the tag: a server
 * cannot restore the original length by trimming it back off.
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
        pad(encodeUtf8(JSON.stringify(payload))),
        aad(context, uuid, PAYLOAD_VERSION),
    );

    const wrappedItemKey = await client.wrapFrom(
        handle,
        vaultKeyHandle(vaultUuid),
        aad('item.key', uuid, KEY_WRAP_VERSION),
    );

    /*
     | The Item Key has no further use — the next write generates another one —
     | so it is dropped rather than left in the keyring for the rest of the
     | session. Bulk opens never store one at all.
     */
    await client.forget(handle);

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
