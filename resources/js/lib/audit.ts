/**
 * Reporting the two events only this tab can see.
 *
 * Unlocking a vault and revealing a secret both happen entirely in the browser.
 * The server watches a page load fetch a whole vault's ciphertext and cannot
 * tell whether the user opened one item or none, so if the browser does not
 * say, the log has a hole exactly where an investigation would look first.
 *
 * **Reporting never fails the thing it is reporting on.** A secret that was
 * revealed *was* revealed; a failed audit write does not un-reveal it, and an
 * error toast over a working feature would train people to ignore errors. So
 * every call here is fire-and-forget and swallows its failure — the one place
 * in this codebase where swallowing an error is right, and it is worth saying
 * why: the alternative is worse in both directions, because a throw would break
 * a working page and a retry queue would hold decrypted subject identifiers in
 * memory past a lock.
 *
 * The cost is honest and stated in docs/02: a client that cannot reach the
 * server records nothing, and the log is a record of what was reported rather
 * than a proof of what happened.
 */
import type { AuditActionName } from '@/crypto/audit';
import { auditTimestamp } from '@/crypto/audit';
import type { CryptoClient } from '@/crypto/worker/client';

import { toBase64 } from './bytes';
import { postJson } from './http';

/**
 * Signs a statement in the Worker and posts it.
 *
 * The signature is what separates "the browser said this happened" from "the
 * server says the browser said so". Without it these would be the only entries
 * in the log the server could invent freely, since they are the only ones it
 * did not witness.
 */
export async function report(
    client: CryptoClient,
    action: AuditActionName,
    subjectUuid: string,
): Promise<void> {
    try {
        const { payload, signature } = await client.signAuditStatement({
            action,
            subjectUuid,
            at: auditTimestamp(),
        });

        await postJson('/audit', {
            action,
            subject_uuid: subjectUuid,
            payload,
            signature: toBase64(signature),
        });
    } catch {
        /*
         | Deliberately silent. `no-console` is enforced across resources/js
         | precisely so nothing downstream of a decrypt is logged, and this call
         | knows the UUID of a secret somebody just looked at.
         |
         | A missing entry is visible where it matters: the chain stays intact,
         | `seq` stays gapless, and what is absent is a report nobody made — not
         | a record somebody removed.
         */
    }
}

/**
 * Records that a vault was unlocked in this tab.
 *
 * Once per vault per unlock, not per page view: navigating between two lockboxes
 * in the same vault is one session with one unlock, and an entry per navigation
 * would drown the entries that matter.
 */
const reported = new Set<string>();

export function reportUnlock(client: CryptoClient, vaultUuid: string): void {
    if (reported.has(vaultUuid)) {
        return;
    }

    reported.add(vaultUuid);

    void report(client, 'vault.unlocked', vaultUuid);
}

export function reportReveal(client: CryptoClient, secretUuid: string): void {
    void report(client, 'secret.revealed', secretUuid);
}

/**
 * Forgets what has been reported, so the next unlock is recorded again.
 *
 * Subscribed to the lock signal by `stores/session.ts`. Without it, locking and
 * unlocking in one tab would record the first unlock and silently skip every
 * one after — which is precisely the sequence somebody investigating would
 * want to see.
 */
export function resetReported(): void {
    reported.clear();
}
