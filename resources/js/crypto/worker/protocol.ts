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
import type { AadParams } from '../aad';
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
    | { op: 'forget'; handle: KeyHandle };

export type ResponseFor<R extends Request['op']> = R extends 'status'
    ? { unlocked: boolean; handles: KeyHandle[] }
    : R extends 'seal' | 'open' | 'wrapFrom' | 'sealToPublicKey'
      ? { bytes: Uint8Array }
      : R extends 'beginUnlock'
        ? { authKey: Uint8Array }
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
