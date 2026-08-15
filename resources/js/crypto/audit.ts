/**
 * Signed statements about things only the browser can see.
 *
 * Unlocking a vault and revealing a secret both happen entirely inside this tab.
 * The Worker unwraps a key; a component renders a string; nothing crosses the
 * network. Those are also the two moments an investigation asks about first —
 * *was my vault opened, and which credentials were actually looked at* — and the
 * server cannot answer either, because a page load fetches a whole vault's
 * ciphertext whether the user opens one item or none.
 *
 * So the browser reports them. And it **signs** them, which is the part that
 * matters: without a signature these would be the only entries in the audit log
 * that the server did not witness *and* could freely invent. With one, a
 * fabricated entry is detectable by anyone who checks, because the server does
 * not hold the key.
 *
 *   signature = Ed25519( "vault:audit:v1" ‖ 0x00 ‖ payload )
 *
 * Domain-separated for the same reason grants are: a self-signature, a grant and
 * an audit statement are all Ed25519 signatures by one key, and without a
 * separator a signature over one could be presented as another.
 *
 * Spec: docs/03-cryptographic-design.md#audit-chain-d9-phase-7
 */
import { ed25519 } from '@noble/curves/ed25519.js';

import { InvalidParameterError } from './errors';
import { concat, utf8ToBytes } from './primitives';

/** Matches AuditStatement::CONTEXT in app/Support/AuditStatement.php. */
export const AUDIT_SIGNATURE_CONTEXT = 'vault:audit:v1';

export const AUDIT_VERSION = 1;

/**
 * The complete set of things the browser may assert.
 *
 * A closed union, not a free string. This is a **signing oracle by another
 * name**: whatever appears here is something injected script can obtain the
 * user's signature on, so the set stays as small as the feature needs and every
 * addition is a deliberate decision about what a signature from this key may
 * come to mean. Server-observed events are not in it — the server does not need
 * the browser's word for what it watched happen.
 */
export const AUDIT_ACTIONS = ['vault.unlocked', 'secret.revealed'] as const;

export type AuditActionName = (typeof AUDIT_ACTIONS)[number];

export interface AuditStatement {
    action: AuditActionName;
    /** The vault that was unlocked, or the secret that was revealed. */
    subjectUuid: string;
    /** ISO 8601, UTC, second precision. */
    at: string;
}

/**
 * Field order for the canonical form.
 *
 * Fixed explicitly rather than left to literal order, exactly as in `grant.ts`:
 * the bytes are what the signature commits to, and two clients disagreeing
 * about the order would produce signatures neither could verify.
 */
const CANONICAL_FIELDS = ['v', 'action', 'subjectUuid', 'at'] as const;

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

const TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

/**
 * Serialises a statement to the exact bytes that get signed and stored.
 *
 * Strict, and throws: this is our own data on the way out, the same asymmetry
 * that runs through `grant.ts`. We are exacting about what we produce and
 * forgiving about how we report what we receive.
 */
export function canonicaliseStatement(statement: AuditStatement): string {
    if (!AUDIT_ACTIONS.includes(statement.action)) {
        throw new InvalidParameterError(
            `An audit statement may only assert one of ${AUDIT_ACTIONS.join(', ')}, ` +
                `received: ${statement.action}. The set is closed because signing one is ` +
                'the only thing this key will do on demand.',
        );
    }

    if (!UUID_PATTERN.test(statement.subjectUuid)) {
        throw new InvalidParameterError(
            `An audit statement subject must be a lowercase UUID, received: ${statement.subjectUuid}`,
        );
    }

    if (!TIMESTAMP_PATTERN.test(statement.at)) {
        throw new InvalidParameterError(
            `An audit statement timestamp must be ISO 8601 UTC to the second, received: ${statement.at}`,
        );
    }

    return JSON.stringify({ v: AUDIT_VERSION, ...statement }, [...CANONICAL_FIELDS]);
}

/** The current time in the format a statement records. */
export function auditTimestamp(at: Date = new Date()): string {
    return `${at.toISOString().slice(0, 19)}Z`;
}

export interface SignedStatement {
    /** The canonical JSON. Stored verbatim, so signatures outlive format changes. */
    payload: string;
    signature: Uint8Array;
}

export function signAuditStatement(ed25519SecretKey: Uint8Array, statement: AuditStatement): SignedStatement {
    const payload = canonicaliseStatement(statement);

    return { payload, signature: ed25519.sign(signaturePayload(payload), ed25519SecretKey) };
}

/**
 * Verifies a statement against a public key.
 *
 * Never throws. Not used by the application — the server checks signatures on
 * the way in and `vault:audit-verify` checks them again — but the round trip is
 * what the tests assert, and a verifier that lived only in PHP would be a
 * verifier nothing here could disagree with.
 */
export function verifyAuditStatement(signature: Uint8Array, payload: string, publicKey: Uint8Array): boolean {
    try {
        return ed25519.verify(signature, signaturePayload(payload), publicKey);
    } catch {
        return false;
    }
}

function signaturePayload(payload: string): Uint8Array {
    return concat(utf8ToBytes(AUDIT_SIGNATURE_CONTEXT), utf8ToBytes('\0'), utf8ToBytes(payload));
}
