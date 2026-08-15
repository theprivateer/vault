/**
 * The Worker message protocol.
 *
 * The contract that matters: **requests may carry key material in, responses
 * never carry key material out.** The main thread holds opaque string handles
 * and asks the Worker to operate on them.
 *
 * That does not solve XSS — injected script can still ask the Worker to decrypt
 * specific items — but it bounds the damage. An attacker cannot lift the User
 * Key and walk away with everything; they have to ask for each item, slowly,
 * and every request is a candidate for the audit log. See adversary A7 in
 * docs/02-threat-model.md.
 */
import type { AadParams, ChunkAadParams } from '../aad';
import type { AuditStatement } from '../audit';
import type { Grant } from '../grant';
import type { KdfParams } from '../primitives';

/**
 * Identifies a key held inside the Worker. This is the "handle" the main thread
 * works with: a label, never bytes.
 */
export type KeyHandle = string;

/** The account key, unwrapped at unlock. */
export const USER_KEY: KeyHandle = 'user';

/**
 * The identity private keys, unwrapped from `user_identities` under the User
 * Key. X25519 opens sealed vault keys; Ed25519 signs grants from Phase 5.
 */
export const X25519_KEY: KeyHandle = 'identity:x25519';

export const ED25519_KEY: KeyHandle = 'identity:ed25519';

/**
 * Handles are derived from UUIDs rather than chosen freely, so two records can
 * never collide on one and silently share a key.
 */
export function vaultKeyHandle(uuid: string): KeyHandle {
    return `vault:${uuid}`;
}

export function itemKeyHandle(uuid: string): KeyHandle {
    return `item:${uuid}`;
}

/**
 * One item in a bulk open: the wrapped Item Key, and the payload it opens.
 *
 * Both halves travel together because they are only ever useful together, and
 * sending them as one unit is what collapses two round trips per item into one
 * for a whole batch. The Item Key is unwrapped, used and zeroised inside the
 * Worker without ever being stored under a handle — nothing needs it again,
 * since every write generates a fresh one.
 */
export interface BulkOpenItem {
    /** The Vault Key handle the Item Key is wrapped under. */
    using: KeyHandle;
    wrapped: Uint8Array;
    keyAad: AadParams;
    envelope: Uint8Array;
    payloadAad: AadParams;
}

/**
 * Per-item success or failure.
 *
 * A batch never fails as a whole for a reason belonging to one item: one
 * unreadable secret must not blank out the twenty beside it, and a batch that
 * threw would make the batch size visible in the interface as a difference in
 * behaviour.
 */
export type BulkOpenResult = { ok: true; bytes: Uint8Array } | { ok: false; error: SerialisedError };

/**
 * One chunk of a file, and the wrapped File Key that covers it.
 *
 * The key travels with every chunk rather than being unwrapped once and held
 * under a handle, for the same reason bulk opens never store an Item Key: a
 * five-hundred-chunk upload would otherwise leave a live file key in the
 * keyring for the whole transfer, and there is nothing it could be needed for
 * afterwards. Unwrapping costs one ChaCha20 pass over 32 bytes per chunk, which
 * against a mebibyte of AES is not measurable.
 */
export interface ChunkRequest {
    /** The Vault Key handle the File Key is wrapped under. */
    using: KeyHandle;
    wrapped: Uint8Array;
    keyAad: AadParams;
    /** Random, per file, from the encrypted manifest. Not secret. */
    noncePrefix: Uint8Array;
    /** Binds the chunk to its file, its index and the file's chunk count. */
    aad: ChunkAadParams;
}

export type Request =
    | {
          op: 'unlock';
          password: string;
          kdfSalt: Uint8Array;
          kdfParams: KdfParams;
          wrappedUserKey: Uint8Array;
          userKeyAad: AadParams;
      }
    /*
     | Login is two steps, because the wrapped User Key is only returned after
     | the server has accepted the auth key. Deriving once and holding the KEK
     | inside the Worker avoids running Argon2id twice, which at production
     | parameters would add roughly three quarters of a second to every login
     | for no security benefit.
     */
    | { op: 'beginUnlock'; password: string; kdfSalt: Uint8Array; kdfParams: KdfParams }
    | { op: 'completeUnlock'; wrappedUserKey: Uint8Array; userKeyAad: AadParams }
    | { op: 'register'; password: string; kdfSalt: Uint8Array; kdfParams: KdfParams; uuid: string }
    | { op: 'beginRecovery'; recoveryCode: string; recoverySalt: Uint8Array }
    | {
          op: 'unlockWithRecovery';
          recoveryCode: string;
          recoverySalt: Uint8Array;
          wrappedUserKey: Uint8Array;
          userKeyAad: AadParams;
      }
    | {
          op: 'rewrapForPassword';
          password: string;
          kdfSalt: Uint8Array;
          kdfParams: KdfParams;
          userKeyAad: AadParams;
      }
    | { op: 'issueRecoveryKit'; userKeyAad: AadParams }
    | { op: 'lock' }
    | { op: 'status' }
    | { op: 'seal'; handle: KeyHandle; plaintext: Uint8Array; aad: AadParams }
    | { op: 'open'; handle: KeyHandle; envelope: Uint8Array; aad: AadParams }
    /*
     | Bulk decryption, and the reason opening a large vault is bearable.
     |
     | Every postMessage is a structured clone plus a task-queue hop, so a
     | thousand secrets opened one at a time is four thousand crossings of the
     | Worker boundary — and the cost of the crossings dwarfs the cost of the
     | XChaCha20 itself. One request per batch makes the boundary a rounding
     | error and leaves the measured time where it belongs, in the cipher.
     */
    | { op: 'openMany'; items: BulkOpenItem[] }
    /*
     | File bodies (Phase 6). One chunk in, one chunk out, and the only pair of
     | operations in the protocol that are genuinely asynchronous — they run
     | AES-GCM through WebCrypto rather than the pure-TS cipher everything else
     | uses. See crypto/chunks.ts for why files get the exception.
     */
    | (ChunkRequest & { op: 'sealChunk'; plaintext: Uint8Array })
    | (ChunkRequest & { op: 'openChunk'; chunk: Uint8Array })
    | { op: 'unwrapInto'; handle: KeyHandle; using: KeyHandle; wrapped: Uint8Array; aad: AadParams }
    /*
     | The item-key operations. Between them they build and walk the lower half
     | of the hierarchy — Vault Key → Item Key → payload — without a single key
     | byte crossing back to the main thread.
     */
    | { op: 'generateInto'; handle: KeyHandle }
    | { op: 'wrapFrom'; handle: KeyHandle; using: KeyHandle; aad: AadParams }
    | { op: 'sealToPublicKey'; handle: KeyHandle; recipientPublicKey: Uint8Array; aad: AadParams }
    | { op: 'openSealedInto'; handle: KeyHandle; using: KeyHandle; sealed: Uint8Array; aad: AadParams }
    /*
     | Signs a membership grant with the held Ed25519 key.
     |
     | Deliberately not a general "sign these bytes" operation. A signing oracle
     | over arbitrary input would let injected script obtain the user's signature
     | on anything the format ever grows to cover — a future audit entry, an
     | identity rotation — from a single foothold. This op takes a grant and
     | applies the grant domain separator itself, so the only statement the
     | Worker will ever sign is one whose shape is known here.
     */
    | { op: 'signGrant'; grant: Grant }
    /*
     | Signs a statement about something only the browser saw — a vault
     | unlocked, a secret revealed.
     |
     | The same discipline as signGrant, and for the same reason: it takes a
     | *statement*, not bytes, and applies the audit domain separator itself.
     | These two ops are together the complete list of things injected script
     | can make this key say, which is why both take closed shapes rather than
     | a buffer.
     */
    | { op: 'signAuditStatement'; statement: AuditStatement }
    | { op: 'forget'; handle: KeyHandle };

export type ResponseFor<R extends Request['op']> = R extends 'status'
    ? { unlocked: boolean; handles: KeyHandle[] }
    : R extends 'seal' | 'open' | 'wrapFrom' | 'sealToPublicKey' | 'sealChunk' | 'openChunk'
      ? { bytes: Uint8Array }
      : R extends 'openMany'
        ? { results: BulkOpenResult[] }
        : R extends 'beginUnlock'
          ? { authKey: Uint8Array }
          : R extends 'signGrant' | 'signAuditStatement'
            ? { payload: string; signature: Uint8Array }
            : Record<string, never>;

export interface Envelope<T> {
    /** Correlates a response with its request. */
    id: number;
    result: T;
}

/**
 * Errors are flattened because class identity does not survive structured
 * cloning — an IntegrityError posted across the boundary would arrive as a
 * plain object and `instanceof` would silently be false. The client
 * reconstructs the right class from `name`.
 */
export interface SerialisedError {
    name: string;
    message: string;
}

export type Reply =
    { id: number; ok: true; result: unknown } | { id: number; ok: false; error: SerialisedError };
