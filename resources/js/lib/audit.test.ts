/**
 * Reporting the two events only the browser can see.
 *
 * What is worth pinning here is not that the request is made — it is the
 * behaviour around failure and repetition, both of which are deliberate
 * decisions that would look like bugs to somebody tidying up later.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { AUDIT_SIGNATURE_CONTEXT, verifyAuditStatement } from '@/crypto/audit';
import { generateIdentity } from '@/crypto/identity';
import { CryptoClient } from '@/crypto/worker/client';
import type { WorkerScope } from '@/crypto/worker/handler';
import { installHandler } from '@/crypto/worker/handler';
import type { Reply, Request } from '@/crypto/worker/protocol';
import { ED25519_KEY, USER_KEY } from '@/crypto/worker/protocol';

import { report, reportReveal, reportUnlock, resetReported } from './audit';
import { fromBase64 } from './bytes';

const VAULT = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f7';
const SECRET = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f8';

class FakeWorker {
    onmessage: ((event: MessageEvent<Reply>) => void) | null = null;

    onerror: ((event: unknown) => void) | null = null;

    private readonly scope: WorkerScope;

    constructor() {
        this.scope = {
            onmessage: null,
            postMessage: (reply: Reply) => {
                queueMicrotask(() => this.onmessage?.({ data: reply } as MessageEvent<Reply>));
            },
        };

        installHandler(this.scope);
    }

    postMessage(message: { id: number; request: Request }): void {
        this.scope.onmessage?.({ data: structuredClone(message) });
    }

    terminate(): void {}
}

let posted: Array<Record<string, unknown>>;
let failNext: boolean;

/** An unlocked client holding a real Ed25519 signing key. */
async function signingClient(): Promise<{ client: CryptoClient; publicKey: Uint8Array }> {
    const client = new CryptoClient(() => new FakeWorker() as unknown as Worker);
    const identity = generateIdentity();

    /*
     | The keyring will only sign with a key it holds, so the key has to get in
     | there the way a real unlock puts it there: generated into a handle, then
     | unwrapped into the identity slot.
     */
    await client.generateInto(USER_KEY);

    const wrapped = await client.seal(USER_KEY, identity.ed25519.secretKey, {
        context: 'user.privkey.ed25519',
        subject: VAULT,
        version: 1,
    });

    await client.unwrapInto({
        handle: ED25519_KEY,
        using: USER_KEY,
        wrapped,
        aad: { context: 'user.privkey.ed25519', subject: VAULT, version: 1 },
    });

    return { client, publicKey: identity.ed25519.publicKey };
}

beforeEach(() => {
    posted = [];
    failNext = false;
    resetReported();

    vi.stubGlobal('document', { cookie: '' });
    vi.stubGlobal('fetch', (_url: string, init?: RequestInit) => {
        if (failNext) {
            return Promise.reject(new TypeError('network down'));
        }

        posted.push(JSON.parse(init?.body as string) as Record<string, unknown>);

        return Promise.resolve(new Response('{}', { status: 200 }));
    });
});

describe('reporting', () => {
    it('posts a statement signed by the account’s own key', async () => {
        const { client, publicKey } = await signingClient();

        await report(client, 'secret.revealed', SECRET);

        const [body] = posted;

        expect(body?.action).toBe('secret.revealed');
        expect(body?.subject_uuid).toBe(SECRET);

        // The signature verifies over the exact bytes that were sent, which is
        // what the server and `vault:audit-verify` both check.
        expect(
            verifyAuditStatement(fromBase64(String(body?.signature)), String(body?.payload), publicKey),
        ).toBe(true);
    });

    it('signs under the audit domain separator, not a bare payload', async () => {
        const { client, publicKey } = await signingClient();

        await report(client, 'vault.unlocked', VAULT);

        const [body] = posted;
        const signature = fromBase64(String(body?.signature));

        expect(verifyAuditStatement(signature, String(body?.payload), publicKey)).toBe(true);
        expect(AUDIT_SIGNATURE_CONTEXT).toBe('vault:audit:v1');
    });

    /*
     | The deliberate swallow, and the one place in this codebase where
     | swallowing an error is right. A secret that was revealed *was* revealed;
     | a failed report does not un-reveal it, and an error over a working
     | feature teaches people to ignore errors.
     */
    it('never throws when the report cannot be delivered', async () => {
        const { client } = await signingClient();

        failNext = true;

        await expect(report(client, 'secret.revealed', SECRET)).resolves.toBeUndefined();
        expect(posted).toEqual([]);
    });

    it('never throws when the vault is locked and there is no key to sign with', async () => {
        const client = new CryptoClient(() => new FakeWorker() as unknown as Worker);

        await expect(report(client, 'secret.revealed', SECRET)).resolves.toBeUndefined();
        expect(posted).toEqual([]);
    });
});

describe('unlocks', () => {
    /*
     | Once per vault per unlock, not per page view. Navigating between two
     | lockboxes in the same vault is one session with one unlock, and an entry
     | per navigation would drown the entries that matter.
     */
    it('reports a vault only once while it stays unlocked', async () => {
        const { client } = await signingClient();

        reportUnlock(client, VAULT);
        reportUnlock(client, VAULT);
        await vi.waitFor(() => expect(posted).toHaveLength(1));

        expect(posted[0]?.action).toBe('vault.unlocked');
    });

    it('reports each vault separately', async () => {
        const { client } = await signingClient();
        const other = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f9';

        reportUnlock(client, VAULT);
        reportUnlock(client, other);

        await vi.waitFor(() => expect(posted).toHaveLength(2));
    });

    /*
     | Locking and unlocking in one tab must record both unlocks. Without the
     | reset, the first would be recorded and every one after it silently
     | skipped — which is precisely the sequence somebody investigating a
     | session would want to see.
     */
    it('reports again after a lock has cleared what was seen', async () => {
        const { client } = await signingClient();

        reportUnlock(client, VAULT);
        await vi.waitFor(() => expect(posted).toHaveLength(1));

        resetReported();
        reportUnlock(client, VAULT);

        await vi.waitFor(() => expect(posted).toHaveLength(2));
    });

    it('reports every reveal, unlike unlocks', async () => {
        const { client } = await signingClient();

        reportReveal(client, SECRET);
        reportReveal(client, SECRET);

        await vi.waitFor(() => expect(posted).toHaveLength(2));
        expect(posted.map((body) => body.action)).toEqual(['secret.revealed', 'secret.revealed']);
    });
});
