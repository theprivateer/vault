/**
 * Signed grants: the statement "I gave this person this role in this vault".
 *
 * A membership row on its own proves nothing. The server writes those rows, so a
 * malicious server can invent one — inserting itself as a member of a vault, or
 * quietly promoting a viewer to an editor. What it cannot do is produce an
 * Ed25519 signature from a key it does not hold, so every grant carries one, and
 * a recipient trusts a vault only once that signature verifies against a public
 * key they have pinned.
 *
 * Two properties do the work, and both are easy to get subtly wrong:
 *
 * 1. **The signature covers the exact bytes that were stored.** `grant_payload`
 *    holds the canonical JSON verbatim rather than being rebuilt from columns at
 *    verification time, so a future change to how grants are serialised cannot
 *    silently invalidate every signature already issued.
 *
 * 2. **The signed grant is then compared against the row it arrived with.** A
 *    valid signature over *some* grant is not evidence about *this* membership.
 *    Without the comparison a server could serve a genuine signed grant for the
 *    viewer role beside a row that says owner, and the check would pass while
 *    describing something else entirely.
 *
 * Spec: docs/03-cryptographic-design.md#sharing-a-vault-d8
 */
import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToHex } from '@noble/hashes/utils.js';

import { InvalidParameterError } from './errors';
import { concat, utf8ToBytes } from './primitives';

/**
 * Domain separator. Without one, a signature made over an identity
 * self-signature payload — or a future audit entry — could be replayed as a
 * grant, since all three are Ed25519 signatures by the same key.
 */
export const GRANT_SIGNATURE_CONTEXT = 'vault:grant:v1';

/**
 * The grant schema version, inside the signed bytes.
 *
 * Present so that an older client refuses a newer grant rather than ignoring
 * fields it does not recognise. Unknown fields are otherwise harmless here —
 * every field that carries authority is checked against the membership row — but
 * "harmless because nothing reads it" stops being true the moment a later
 * version gives one meaning.
 */
export const GRANT_VERSION = 1;

const SIGNATURE_LENGTH = 64;

const PUBLIC_KEY_LENGTH = 32;

export type GrantRole = 'owner' | 'editor' | 'viewer';

const ROLES: readonly GrantRole[] = ['owner', 'editor', 'viewer'];

export interface Grant {
    vaultUuid: string;
    recipientUuid: string;
    /**
     * The recipient's fingerprint, lowercase hex.
     *
     * Binding the grant to the recipient's *key* rather than only their account
     * is what stops a server swapping in a public key of its own and replaying
     * an otherwise genuine grant against it. The recipient checks this against
     * the fingerprint of the keys they actually hold.
     */
    recipientFingerprint: string;
    role: GrantRole;
    keyEpoch: number;
    /** ISO 8601, UTC, second precision. */
    grantedAt: string;
}

/**
 * Field order for the canonical form.
 *
 * Fixed explicitly rather than left to object literal order or a sort, because
 * the bytes here are what a signature commits to: two clients that disagreed
 * about the ordering would produce signatures neither could verify.
 */
const CANONICAL_FIELDS = [
    'v',
    'vaultUuid',
    'recipientUuid',
    'recipientFingerprint',
    'role',
    'keyEpoch',
    'grantedAt',
] as const;

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

const FINGERPRINT_PATTERN = /^[0-9a-f]{64}$/;

const TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

/**
 * Serialises a grant to the exact bytes that get signed and stored.
 *
 * Throws on invalid input, because a grant being written is our own data — the
 * asymmetry with `verifyGrant`, which never throws, is the same one that runs
 * through `identity.ts`: we are strict about what we produce and forgiving about
 * how we report what we receive.
 */
export function canonicaliseGrant(grant: Grant): string {
    assertUuid(grant.vaultUuid, 'vaultUuid');
    assertUuid(grant.recipientUuid, 'recipientUuid');

    if (!FINGERPRINT_PATTERN.test(grant.recipientFingerprint)) {
        throw new InvalidParameterError(
            `Grant recipientFingerprint must be 64 lowercase hex characters, received: ${grant.recipientFingerprint}`,
        );
    }

    if (!ROLES.includes(grant.role)) {
        throw new InvalidParameterError(`Grant role must be one of ${ROLES.join(', ')}.`);
    }

    if (!Number.isSafeInteger(grant.keyEpoch) || grant.keyEpoch < 1) {
        throw new InvalidParameterError(
            `Grant keyEpoch must be a positive integer, received: ${grant.keyEpoch}`,
        );
    }

    if (!TIMESTAMP_PATTERN.test(grant.grantedAt)) {
        throw new InvalidParameterError(
            `Grant grantedAt must be ISO 8601 UTC to the second, received: ${grant.grantedAt}`,
        );
    }

    return JSON.stringify({ v: GRANT_VERSION, ...grant }, [...CANONICAL_FIELDS]);
}

/** The current time in the format a grant records, for the granting client. */
export function grantTimestamp(at: Date = new Date()): string {
    return `${at.toISOString().slice(0, 19)}Z`;
}

export interface SignedGrant {
    /** The canonical JSON. Stored verbatim, so signatures outlive format changes. */
    payload: string;
    signature: Uint8Array;
}

export function signGrant(ed25519SecretKey: Uint8Array, grant: Grant): SignedGrant {
    const payload = canonicaliseGrant(grant);

    return { payload, signature: ed25519.sign(signaturePayload(payload), ed25519SecretKey) };
}

export type GrantFailure =
    /** The payload is not a grant this client can read. */
    | 'malformed'
    /** The signature does not verify against the granter's public key. */
    | 'signature'
    /** It verified, but it describes a different grant than the one on offer. */
    | 'mismatch';

export type GrantVerdict =
    { valid: true; grant: Grant } | { valid: false; reason: GrantFailure; detail: string };

/**
 * What a membership row claims, for comparison against the signed grant.
 *
 * `grantedAt` is optional and never compared: it is the granter's assertion
 * about when they acted, not something the row independently attests, and
 * comparing it would turn ordinary clock skew into a tampering report.
 */
export type GrantClaims = Omit<Grant, 'grantedAt'> & { grantedAt?: string };

/**
 * Verifies a grant against the granter's public key **and** against the
 * membership it claims to authorise.
 *
 * `expected` is what the server said the row contains. Passing it is not
 * optional plumbing: a signature proves only that the granter once signed the
 * bytes in `payload`, and it is the comparison that turns that into evidence
 * about *this* row. A server holding any genuine signed grant could otherwise
 * attach it to a fabricated membership with a role of its choosing.
 *
 * **Never throws.** Every input here came from the server and is untrusted, so
 * malformed JSON, a wrong-length key and a forged signature are all ordinary
 * conditions that render as a warning rather than an exception.
 */
export function verifyGrant(
    signature: Uint8Array,
    payload: string,
    granterEd25519PublicKey: Uint8Array,
    expected: GrantClaims,
): GrantVerdict {
    const grant = parseGrant(payload);

    if (!grant) {
        return { valid: false, reason: 'malformed', detail: 'The signed grant could not be read.' };
    }

    if (signature.length !== SIGNATURE_LENGTH || granterEd25519PublicKey.length !== PUBLIC_KEY_LENGTH) {
        return {
            valid: false,
            reason: 'signature',
            detail: 'The signature or the granter’s public key is the wrong length.',
        };
    }

    if (!verifySignature(signature, payload, granterEd25519PublicKey)) {
        return {
            valid: false,
            reason: 'signature',
            detail: 'The signature does not match the granter’s key. It was not issued by them.',
        };
    }

    const difference = firstDifference(grant, expected);

    if (difference) {
        return {
            valid: false,
            reason: 'mismatch',
            detail: `The signed grant says ${difference}, which is not what this membership claims.`,
        };
    }

    return { valid: true, grant };
}

/**
 * Parses without re-canonicalising.
 *
 * Deliberately not "canonicalise it again and compare the strings": that would
 * make every signature invalid the day the serialisation changes, which is the
 * one thing storing the exact bytes exists to prevent. Safety comes from the
 * version check and from every meaningful field being compared against the row
 * afterwards, not from the byte-for-byte shape of the JSON.
 */
export function parseGrant(payload: string): Grant | null {
    let parsed: unknown;

    try {
        parsed = JSON.parse(payload);
    } catch {
        return null;
    }

    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
        return null;
    }

    const fields = parsed as Record<string, unknown>;

    if (fields.v !== GRANT_VERSION) {
        return null;
    }

    const { vaultUuid, recipientUuid, recipientFingerprint, role, keyEpoch, grantedAt } = fields;

    const wellFormed =
        isUuid(vaultUuid) &&
        isUuid(recipientUuid) &&
        typeof recipientFingerprint === 'string' &&
        FINGERPRINT_PATTERN.test(recipientFingerprint) &&
        typeof role === 'string' &&
        ROLES.includes(role as GrantRole) &&
        typeof keyEpoch === 'number' &&
        Number.isSafeInteger(keyEpoch) &&
        keyEpoch >= 1 &&
        typeof grantedAt === 'string' &&
        TIMESTAMP_PATTERN.test(grantedAt);

    if (!wellFormed) {
        return null;
    }

    return {
        vaultUuid,
        recipientUuid,
        recipientFingerprint,
        role: role as GrantRole,
        keyEpoch,
        grantedAt,
    };
}

/** Renders a fingerprint for a grant: lowercase hex, the full 256 bits. */
export function fingerprintHex(fingerprint: Uint8Array): string {
    return bytesToHex(fingerprint);
}

/**
 * The first field on which the signed grant and the offered membership disagree,
 * named for the interface, or null when they agree.
 */
function firstDifference(signed: Grant, expected: GrantClaims): string | null {
    const comparisons: ReadonlyArray<readonly [string, string, string]> = [
        ['a different vault', signed.vaultUuid, expected.vaultUuid],
        ['a different recipient', signed.recipientUuid, expected.recipientUuid],
        [
            'a different set of keys for the recipient',
            signed.recipientFingerprint,
            expected.recipientFingerprint,
        ],
        [`the role “${signed.role}”`, signed.role, expected.role],
        [`key epoch ${signed.keyEpoch}`, String(signed.keyEpoch), String(expected.keyEpoch)],
    ];

    for (const [description, actual, wanted] of comparisons) {
        if (actual !== wanted) {
            return description;
        }
    }

    return null;
}

function verifySignature(signature: Uint8Array, payload: string, publicKey: Uint8Array): boolean {
    try {
        return ed25519.verify(signature, signaturePayload(payload), publicKey);
    } catch {
        return false;
    }
}

function signaturePayload(payload: string): Uint8Array {
    return concat(utf8ToBytes(GRANT_SIGNATURE_CONTEXT), utf8ToBytes('\0'), utf8ToBytes(payload));
}

function isUuid(value: unknown): value is string {
    return typeof value === 'string' && UUID_PATTERN.test(value);
}

function assertUuid(value: string, field: string): void {
    if (!UUID_PATTERN.test(value)) {
        throw new InvalidParameterError(`Grant ${field} must be a lowercase UUID, received: ${value}`);
    }
}
