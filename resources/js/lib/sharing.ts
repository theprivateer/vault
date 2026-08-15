/**
 * Deciding whether to trust an identity, and whether to trust a grant.
 *
 * Both questions are asked about data the server supplied, and the server is the
 * adversary this whole layer exists to detect. So nothing here believes anything
 * it is told when it can check instead:
 *
 * - **The fingerprint is recomputed, never read.** `user_identities.fingerprint`
 *   is a cache. A server that substituted a public key would naturally also
 *   substitute the fingerprint beside it, so comparing the served fingerprint
 *   against the pin would compare two of the attacker's own values and agree.
 * - **The self-signature is verified before anything else.** It proves the two
 *   public keys were published by whoever holds the Ed25519 private key. That is
 *   necessary and nowhere near sufficient — a server generating its own keypair
 *   satisfies it perfectly — which is exactly why the pin store exists.
 * - **A grant is checked against the granter's *pinned* key.** Verifying it
 *   against the key the server just handed over would be asking the forger
 *   whether the forgery is genuine.
 *
 * Kept framework-free so the decisions can be tested directly rather than
 * through a component.
 */
import type { Grant, GrantClaims, GrantRole, GrantVerdict } from '@/crypto/grant';
import { fingerprintHex, verifyGrant } from '@/crypto/grant';
import { computeFingerprint, verifyPublicKeys } from '@/crypto/identity';

import { fromBase64 } from './bytes';
import { checkPin, type PinMap } from './pins';

/** A public key bundle as `/users/{handle}/identity` returns it. */
export interface PublicIdentity {
    uuid: string;
    displayName: string;
    handle: string;
    x25519PublicKey: string;
    ed25519PublicKey: string;
    selfSignature: string;
    /** The server's cached copy. Recomputed here and otherwise ignored. */
    fingerprint: string;
}

export type IdentityStatus =
    /** The bundle does not hold together: no share can be built from it. */
    | 'invalid'
    /** Well formed, never seen before. Needs an out-of-band comparison. */
    | 'unverified'
    /** Well formed and matching what was pinned. */
    | 'verified'
    /** Well formed, pinned before, and **different**. Stop. */
    | 'changed';

export interface IdentityCheck {
    status: IdentityStatus;
    /** The recomputed fingerprint, lowercase hex. Empty when invalid. */
    fingerprint: string;
    /** What was pinned previously, when the status is `changed`. */
    pinned: string;
    /** Why, in words the interface can show without rewriting. */
    detail: string;
}

export function checkIdentity(identity: PublicIdentity, pins: PinMap): IdentityCheck {
    let ed25519PublicKey: Uint8Array;
    let x25519PublicKey: Uint8Array;
    let selfSignature: Uint8Array;

    try {
        ed25519PublicKey = fromBase64(identity.ed25519PublicKey);
        x25519PublicKey = fromBase64(identity.x25519PublicKey);
        selfSignature = fromBase64(identity.selfSignature);
    } catch {
        return invalid('The published keys are not readable.');
    }

    if (!verifyPublicKeys(selfSignature, ed25519PublicKey, x25519PublicKey)) {
        return invalid(
            'These keys do not carry a valid signature from the account they belong to, so there ' +
                'is no evidence they were published by that person.',
        );
    }

    /*
     | Recomputed from the keys themselves. The served fingerprint is only
     | compared afterwards, and a disagreement is reported rather than resolved
     | in the server's favour — it means the server is describing keys other
     | than the ones it sent, which is not a condition to proceed through.
     */
    const fingerprint = fingerprintHex(computeFingerprint(ed25519PublicKey, x25519PublicKey));

    if (!matchesServedFingerprint(identity.fingerprint, fingerprint)) {
        return invalid('The fingerprint the server published does not match the keys it sent alongside it.');
    }

    const verdict = checkPin(pins, identity.uuid, fingerprint);

    if (verdict.status === 'match') {
        return { status: 'verified', fingerprint, pinned: fingerprint, detail: 'Verified previously.' };
    }

    if (verdict.status === 'changed') {
        return {
            status: 'changed',
            fingerprint,
            pinned: verdict.pinned,
            detail:
                'These are not the keys you verified for this person before. That happens when ' +
                'someone reinstalls or rotates their keys — and it is also exactly what a server ' +
                'substituting its own key looks like. The two are indistinguishable from here.',
        };
    }

    return {
        status: 'unverified',
        fingerprint,
        pinned: '',
        detail: 'You have not verified these keys before.',
    };
}

/** A membership as the server describes it, for the recipient to check. */
export interface MembershipRecord {
    uuid: string;
    role: GrantRole;
    keyEpoch: number;
    acceptedAt: string | null;
    grantSignature: string | null;
    grantPayload: string | null;
    grantedBy: PublicIdentity | null;
    member: { uuid: string; displayName: string; handle: string };
}

export type MembershipTrust =
    | { trusted: true; grant: Grant }
    | { trusted: false; reason: 'unsigned' | 'granter' | 'grant'; detail: string };

/**
 * Whether a membership is one the recipient should treat as a real grant.
 *
 * A vault that fails this renders as a warning, not as a vault. The server can
 * insert a membership row at will — that is a write to a table it owns — and the
 * only thing it cannot manufacture is the granter's signature. So an
 * unverifiable grant is not a degraded vault; it is a claim with nothing behind
 * it.
 */
export function checkMembership(
    membership: MembershipRecord,
    ownFingerprint: string,
    vaultUuid: string,
    pins: PinMap,
): MembershipTrust {
    if (
        membership.grantSignature === null ||
        membership.grantPayload === null ||
        membership.grantedBy === null
    ) {
        return {
            trusted: false,
            reason: 'unsigned',
            detail:
                'This membership carries no signed grant, so there is nothing to show it was ' +
                'issued by a person rather than written into the database.',
        };
    }

    const granter = checkIdentity(membership.grantedBy, pins);

    if (granter.status !== 'verified') {
        return {
            trusted: false,
            reason: 'granter',
            detail:
                granter.status === 'changed'
                    ? `The keys of whoever granted this have changed since you verified them. ${granter.detail}`
                    : 'You have not verified the keys of whoever granted this, so their signature ' +
                      'cannot be checked against anything you trust.',
        };
    }

    const expected: GrantClaims = {
        vaultUuid,
        recipientUuid: membership.member.uuid,
        /*
         | The recipient's *own* fingerprint, recomputed from the keys in their
         | own browser rather than taken from the row. This is what stops a
         | server replaying a genuine grant against a public key it substituted:
         | the grant names the keys it was issued for, and those are not these.
         */
        recipientFingerprint: ownFingerprint,
        role: membership.role,
        keyEpoch: membership.keyEpoch,
    };

    let signature: Uint8Array;

    try {
        signature = fromBase64(membership.grantSignature);
    } catch {
        return { trusted: false, reason: 'grant', detail: 'The signature on this grant is not readable.' };
    }

    const verdict: GrantVerdict = verifyGrant(
        signature,
        membership.grantPayload,
        fromBase64(membership.grantedBy.ed25519PublicKey),
        expected,
    );

    if (!verdict.valid) {
        return { trusted: false, reason: 'grant', detail: verdict.detail };
    }

    return { trusted: true, grant: verdict.grant };
}

function matchesServedFingerprint(served: string, computed: string): boolean {
    try {
        return fingerprintHex(fromBase64(served)) === computed;
    } catch {
        return false;
    }
}

function invalid(detail: string): IdentityCheck {
    return { status: 'invalid', fingerprint: '', pinned: '', detail };
}
