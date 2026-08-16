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
import { verifyRotation } from '@/crypto/rotation';

import { fromBase64 } from './bytes';
import { checkPin, type PinMap } from './pins';

/**
 * The identity this one replaced, and the notice that replaced it.
 *
 * Served alongside the current keys so a peer whose pin no longer matches can
 * tell a rotation from a substitution. The retired *public keys* travel with it
 * because a pin is a fingerprint, and a fingerprint cannot verify a signature —
 * the peer recomputes the fingerprint from these two keys, checks it against
 * their own pin, and only then does the signature mean anything.
 */
export interface RotationNotice {
    x25519PublicKey: string;
    ed25519PublicKey: string;
    selfSignature: string;
    fingerprint: string;
    /** The canonical statement, byte-exact as it was signed. */
    payload: string;
    signature: string;
    rotatedAt: string;
}

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
    /** Null until this account has rotated. One link back, never a chain. */
    rotation?: RotationNotice | null;
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
    /**
     * Whether the keys you pinned signed a notice introducing these ones.
     *
     * Only meaningful when the status is `changed`, and **it is not an accept**.
     * A stolen key signs a valid notice, which is the case rotation most often
     * exists for — so this narrows "someone substituted a key" to "either they
     * rotated, or whoever took their old key did". The interface still refuses
     * to continue without an out-of-band check, and says which of the two
     * situations it is looking at rather than showing one screen for both.
     */
    certified: boolean;
    /** When the notice says the change happened, ISO 8601. Empty otherwise. */
    rotatedAt: string;
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
        return {
            status: 'verified',
            fingerprint,
            pinned: fingerprint,
            detail: 'Verified previously.',
            certified: false,
            rotatedAt: '',
        };
    }

    if (verdict.status === 'changed') {
        return changed(identity, fingerprint, verdict.pinned);
    }

    return {
        status: 'unverified',
        fingerprint,
        pinned: '',
        detail: 'You have not verified these keys before.',
        certified: false,
        rotatedAt: '',
    };
}

/**
 * A changed pin, and whether the keys you pinned vouched for the new ones.
 *
 * The status is `changed` either way — nothing here can produce an accept, and
 * every caller still refuses to continue. What a certified notice changes is
 * what the person is told, and that matters: shown the same red screen for a
 * colleague's routine rotation and for an active attack, people learn to click
 * through it. Distinguishing them is what keeps the stop meaningful.
 */
function changed(identity: PublicIdentity, fingerprint: string, pinned: string): IdentityCheck {
    const uncertified: IdentityCheck = {
        status: 'changed',
        fingerprint,
        pinned,
        detail:
            'These are not the keys you verified for this person before. That happens when ' +
            'someone reinstalls or rotates their keys — and it is also exactly what a server ' +
            'substituting its own key looks like. The two are indistinguishable from here.',
        certified: false,
        rotatedAt: '',
    };

    const notice = identity.rotation;

    if (!notice) {
        return uncertified;
    }

    let retiredEd25519: Uint8Array;
    let retiredX25519: Uint8Array;
    let signature: Uint8Array;

    try {
        retiredEd25519 = fromBase64(notice.ed25519PublicKey);
        retiredX25519 = fromBase64(notice.x25519PublicKey);
        signature = fromBase64(notice.signature);
    } catch {
        return uncertified;
    }

    /*
     | The retired keys are supplied by the server, so the first thing to
     | establish is that they are the keys *this browser* pinned. Verifying the
     | notice against a key the server chose would be asking the forger whether
     | the forgery is genuine — the pin is the only thing here that did not come
     | from the server.
     */
    const retiredFingerprint = fingerprintHex(computeFingerprint(retiredEd25519, retiredX25519));

    if (retiredFingerprint !== pinned) {
        return uncertified;
    }

    const verdict = verifyRotation(signature, notice.payload, retiredEd25519, {
        userUuid: identity.uuid,
        previousFingerprint: pinned,
        fingerprint,
    });

    if (!verdict.certified) {
        return uncertified;
    }

    return {
        status: 'changed',
        fingerprint,
        pinned,
        detail:
            'The keys you verified before signed a notice introducing these ones. That is what a ' +
            'genuine rotation looks like — and it is also what it looks like when somebody who took ' +
            'their old key rotates to one of their own. Check the new fingerprint with them.',
        certified: true,
        rotatedAt: verdict.statement.rotatedAt,
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
    /**
     * Fingerprints this account used to have, from `auth.previousFingerprints`.
     *
     * A grant names the keys it was issued for, so after rotating your own
     * identity every grant anybody made you names a fingerprint you no longer
     * hold — and every shared vault would render as unverifiable because of a
     * change you made yourself. Accepting a grant issued to a former identity of
     * yours is correct: it is still a true statement by the granter about you.
     *
     * Safe to take from the server, precisely because it can only let a check
     * succeed and never forge one. Verifying still needs the granter's signature
     * over a grant naming both that fingerprint and your account, and that is the
     * thing a server cannot produce.
     */
    previousFingerprints: readonly string[] = [],
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

    let signature: Uint8Array;

    try {
        signature = fromBase64(membership.grantSignature);
    } catch {
        return { trusted: false, reason: 'grant', detail: 'The signature on this grant is not readable.' };
    }

    const granterKey = fromBase64(membership.grantedBy.ed25519PublicKey);

    /*
     | Current identity first, then any this account has retired. Ordered that
     | way because the common case is the first entry and because a failure
     | should be reported against the keys the user actually holds — telling
     | somebody their grant does not match a fingerprint they stopped using in
     | March would name the least useful of the mismatches.
     */
    let firstFailure: GrantVerdict | null = null;

    for (const recipientFingerprint of [ownFingerprint, ...previousFingerprints]) {
        const expected: GrantClaims = {
            vaultUuid,
            recipientUuid: membership.member.uuid,
            /*
             | The recipient's *own* fingerprint, recomputed from the keys in
             | their own browser rather than taken from the row. This is what
             | stops a server replaying a genuine grant against a public key it
             | substituted: the grant names the keys it was issued for, and those
             | are not these.
             */
            recipientFingerprint,
            role: membership.role,
            keyEpoch: membership.keyEpoch,
        };

        const verdict: GrantVerdict = verifyGrant(signature, membership.grantPayload, granterKey, expected);

        if (verdict.valid) {
            return { trusted: true, grant: verdict.grant };
        }

        firstFailure ??= verdict;

        /*
         | Only a fingerprint mismatch is worth retrying. A bad signature or a
         | wrong role fails identically against every identity this account has
         | ever had, and looping would turn one clear answer into N of the same.
         */
        if (verdict.reason !== 'mismatch') {
            break;
        }
    }

    return {
        trusted: false,
        reason: 'grant',
        detail: firstFailure?.valid === false ? firstFailure.detail : 'This grant could not be checked.',
    };
}

function matchesServedFingerprint(served: string, computed: string): boolean {
    try {
        return fingerprintHex(fromBase64(served)) === computed;
    } catch {
        return false;
    }
}

function invalid(detail: string): IdentityCheck {
    return { status: 'invalid', fingerprint: '', pinned: '', detail, certified: false, rotatedAt: '' };
}
