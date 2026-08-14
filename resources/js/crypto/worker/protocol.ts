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

export type Request =
    | {
          op: 'unlock';
          password: string;
          kdfSalt: Uint8Array;
          kdfParams: KdfParams;
          wrappedUserKey: Uint8Array;
          userKeyAad: AadParams;
      }
    | { op: 'lock' }
    | { op: 'status' }
    | { op: 'seal'; handle: KeyHandle; plaintext: Uint8Array; aad: AadParams }
    | { op: 'open'; handle: KeyHandle; envelope: Uint8Array; aad: AadParams }
    | { op: 'unwrapInto'; handle: KeyHandle; using: KeyHandle; wrapped: Uint8Array; aad: AadParams };

export type ResponseFor<R extends Request['op']> = R extends 'status'
    ? { unlocked: boolean; handles: KeyHandle[] }
    : R extends 'seal' | 'open'
      ? { bytes: Uint8Array }
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
