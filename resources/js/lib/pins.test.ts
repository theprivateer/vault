import { describe, expect, it } from 'vitest';

import { CryptoClient } from '@/crypto/worker/client';
import { installHandler, type WorkerScope } from '@/crypto/worker/handler';
import type { Reply, Request } from '@/crypto/worker/protocol';

import { toBase64 } from './bytes';
import { checkPin, openPins, sealPins, withPin, type PinMap } from './pins';

const USER_UUID = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f6';
const OTHER_UUID = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f7';

const FAST_KDF = { m: 8, t: 1, p: 1 };

const FINGERPRINT = 'a'.repeat(64);

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
        // structuredClone, exactly as a real Worker would. See .ai/rules/worker.md.
        this.scope.onmessage?.({ data: structuredClone(message) });
    }

    terminate(): void {}
}

async function unlockedClient(): Promise<CryptoClient> {
    const client = new CryptoClient(() => new FakeWorker() as unknown as Worker);

    await client.register({
        password: 'correct horse battery staple',
        kdfSalt: new Uint8Array(16),
        kdfParams: FAST_KDF,
        uuid: USER_UUID,
    });

    return client;
}

describe('checkPin', () => {
    it('reports an identity it has never seen as unknown', () => {
        expect(checkPin({}, OTHER_UUID, FINGERPRINT)).toEqual({ status: 'unknown' });
    });

    it('reports a matching fingerprint as a match', () => {
        expect(checkPin({ [OTHER_UUID]: FINGERPRINT }, OTHER_UUID, FINGERPRINT)).toEqual({
            status: 'match',
        });
    });

    /** The hard stop, at its smallest. */
    it('reports a different fingerprint as changed, and says what was pinned', () => {
        const pinned = 'b'.repeat(64);

        expect(checkPin({ [OTHER_UUID]: pinned }, OTHER_UUID, FINGERPRINT)).toEqual({
            status: 'changed',
            pinned,
        });
    });

    it("does not confuse one identity's pin for another's", () => {
        expect(checkPin({ [USER_UUID]: FINGERPRINT }, OTHER_UUID, FINGERPRINT)).toEqual({
            status: 'unknown',
        });
    });
});

describe('withPin', () => {
    it('adds without mutating the map it was given', () => {
        const before: PinMap = {};
        const after = withPin(before, OTHER_UUID, FINGERPRINT);

        expect(before).toEqual({});
        expect(after).toEqual({ [OTHER_UUID]: FINGERPRINT });
    });

    it('replaces an existing pin, which is what re-verifying means', () => {
        const updated = withPin({ [OTHER_UUID]: 'b'.repeat(64) }, OTHER_UUID, FINGERPRINT);

        expect(updated[OTHER_UUID]).toBe(FINGERPRINT);
    });
});

describe('sealing and opening', () => {
    it('round-trips a pin map through the worker', async () => {
        const client = await unlockedClient();
        const pins = { [OTHER_UUID]: FINGERPRINT, [USER_UUID]: 'c'.repeat(64) };

        const sealed = await sealPins(client, USER_UUID, pins);

        expect(await openPins(client, USER_UUID, sealed)).toEqual(pins);
    });

    it('round-trips an empty map', async () => {
        const client = await unlockedClient();

        expect(await openPins(client, USER_UUID, await sealPins(client, USER_UUID, {}))).toEqual({});
    });

    /**
     * Unpadded, the stored length is a direct count of how many people have been
     * verified — a piece of the sharing graph the server would otherwise get for
     * free, on a row it holds anyway.
     *
     * Padding coarsens that count rather than hiding it. An entry is about 108
     * bytes, so at one or two pins the bucket and the count still nearly
     * coincide; from three upwards the buckets start collapsing ranges together,
     * and the collapsing widens as the list grows. That is the real property, so
     * it is what gets asserted — claiming the size says nothing about the count
     * would be claiming more than the scheme delivers.
     */
    it('pads to buckets, so a range of counts stores at one size', async () => {
        const client = await unlockedClient();

        const withCount = async (count: number) => {
            const pins: PinMap = {};

            for (let n = 0; n < count; n++) {
                pins[`0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e${n.toString(16).padStart(3, '0')}`] = FINGERPRINT;
            }

            return (await sealPins(client, USER_UUID, pins)).length;
        };

        expect(await withCount(3)).toBe(await withCount(4));
        expect(await withCount(5)).toBe(await withCount(9));
    });

    /**
     * Bound to the owner's own UUID. A server that could hand one user's store
     * to another would be handing over trust decisions they never made.
     */
    it('refuses to open a store bound to a different account', async () => {
        const client = await unlockedClient();

        const sealed = await sealPins(client, USER_UUID, { [OTHER_UUID]: FINGERPRINT });

        await expect(openPins(client, OTHER_UUID, sealed)).rejects.toThrow();
    });

    it('refuses a tampered store rather than returning part of it', async () => {
        const client = await unlockedClient();

        const sealed = await sealPins(client, USER_UUID, { [OTHER_UUID]: FINGERPRINT });
        const bytes = Uint8Array.from(atob(sealed), (character) => character.charCodeAt(0));
        // Non-null: a sealed envelope is well over 40 bytes.
        bytes.set([bytes[40]! ^ 0x01], 40);

        await expect(openPins(client, USER_UUID, toBase64(bytes))).rejects.toThrow();
    });

    /**
     * A value that is not a fingerprint would make `checkPin` answer "unknown"
     * for that identity — downgrading a hard stop to a first-sight prompt, which
     * is precisely the outcome an attacker wants. So it is an error.
     */
    it('refuses a store whose contents are not fingerprints', async () => {
        const client = await unlockedClient();

        const sealed = await sealPins(client, USER_UUID, { [OTHER_UUID]: 'not-a-fingerprint' });

        await expect(openPins(client, USER_UUID, sealed)).rejects.toThrow(/corrupt/);
    });

    it('refuses a store that decrypts to something that is not a map', async () => {
        const client = await unlockedClient();

        // Sealed through the same path, so the tag verifies and only the shape
        // check stands between this and being used as a pin map.
        const sealed = await sealPins(client, USER_UUID, ['a', 'b'] as unknown as PinMap);

        await expect(openPins(client, USER_UUID, sealed)).rejects.toThrow(/not readable/);
    });
});
