/**
 * Re-sealing a vault's payloads at the current envelope version.
 *
 * The property that matters is the one that is easiest to lose: **the plaintext
 * must survive exactly**. A re-seal that produced a well-formed, correctly bound
 * envelope around slightly different bytes would pass every downstream check in
 * the application, so the round trip is asserted against the original rather
 * than against a shape.
 *
 * The second is the guard: `previousDigest` has to describe the ciphertext the
 * payload came out of, because that is the only thing standing between this
 * feature and a stale tab writing hour-old plaintext over a newer edit.
 */
import { describe, expect, it } from 'vitest';

import { ENVELOPE_VERSION, LEGACY_ENVELOPE_VERSION, seal } from '@/crypto/envelope';
import { hash256, randomBytes } from '@/crypto/primitives';
import { CryptoClient } from '@/crypto/worker/client';
import { installHandler, type WorkerScope } from '@/crypto/worker/handler';
import type { Reply, Request } from '@/crypto/worker/protocol';
import { vaultKeyHandle } from '@/crypto/worker/protocol';

import { fromBase64, toBase64 } from './bytes';
import { openAll } from './decrypt';
import type { SecretPayload } from './items';
import { batched, isLegacyEnvelope, needsReseal, resealItem, type ResealCandidate } from './reseal';

const VAULT = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f0';
const SECRET = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f1';

/**
 * A Worker stand-in running the real handler in-process, as
 * `crypto/worker/client.test.ts` does it.
 *
 * The genuine keyring rather than a stub, because the property under test is
 * that plaintext survives a real seal and a real open — a stub would prove that
 * this module calls the functions it calls.
 */
class FakeWorker implements Pick<Worker, 'postMessage' | 'terminate' | 'onmessage' | 'onerror'> {
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

/** An unlocked client holding a vault key, ready to seal under it. */
async function unlocked(): Promise<CryptoClient> {
    const crypto = new CryptoClient(() => new FakeWorker() as unknown as Worker);

    await crypto.register({
        password: 'correct horse',
        kdfSalt: randomBytes(16),
        kdfParams: { m: 8, t: 1, p: 1 },
        uuid: VAULT,
    });

    await crypto.generateInto(vaultKeyHandle(VAULT));

    return crypto;
}

const payload: SecretPayload = {
    type: 'password',
    key: 'Router — production',
    value: 'hunter2 🔐',
    notes: 'line one\nline two',
};

describe('spotting what is behind', () => {
    it('recognises an old envelope by its version byte', () => {
        const key = randomBytes(32);
        const aad = { context: 'secret.payload', subject: SECRET, version: 2 } as const;

        const current = seal(key, new TextEncoder().encode('x'), aad);
        const legacy = Uint8Array.from(current);
        legacy[0] = LEGACY_ENVELOPE_VERSION;

        expect(isLegacyEnvelope(toBase64(current))).toBe(false);
        expect(isLegacyEnvelope(toBase64(legacy))).toBe(true);
    });

    /*
     | Something this client cannot parse is not something it should re-seal:
     | re-sealing needs a successful decrypt first, which would have failed
     | anyway. Answering `false` keeps it out of the work list rather than into
     | it.
     */
    it('answers false for anything unreadable rather than volunteering it', () => {
        expect(isLegacyEnvelope('not base64 !!')).toBe(false);
        expect(isLegacyEnvelope('')).toBe(false);
    });

    it('selects only the candidates that are behind', () => {
        const record = (uuid: string, version: number) => ({
            uuid,
            payloadCt: toBase64(Uint8Array.from([version, 1, ...randomBytes(41)])),
            wrappedItemKey: '',
            payloadVersion: 2,
        });

        const candidates: Array<ResealCandidate<unknown>> = [
            { record: record(SECRET, LEGACY_ENVELOPE_VERSION), context: 'secret.payload', payload: {} },
            { record: record(VAULT, ENVELOPE_VERSION), context: 'vault.payload', payload: {} },
        ];

        expect(needsReseal(candidates).map((c) => c.record.uuid)).toEqual([SECRET]);
    });
});

describe('re-sealing an item', () => {
    /*
     | The whole point, and the one failure that would be silent: a re-seal that
     | changed the bytes would still produce a well-formed envelope, correctly
     | bound to the right record, that every check in the application accepts.
     */
    it('round-trips the payload byte for byte, at the current version', async () => {
        const crypto = await unlocked();

        const sealed = await resealItem(crypto, VAULT, {
            record: {
                uuid: SECRET,
                payloadCt: toBase64(randomBytes(43)),
                wrappedItemKey: '',
                payloadVersion: 2,
            },
            context: 'secret.payload',
            payload,
        });

        expect(fromBase64(sealed.payload_ct)[0]).toBe(ENVELOPE_VERSION);

        const [opened] = await openAll<
            { uuid: string; payloadCt: string; wrappedItemKey: string; payloadVersion: number },
            SecretPayload
        >(
            crypto,
            VAULT,
            'secret.payload',
            [
                {
                    uuid: SECRET,
                    payloadCt: sealed.payload_ct,
                    wrappedItemKey: sealed.wrapped_item_key,
                    payloadVersion: sealed.payload_version,
                },
            ],
            () => 'the re-sealed secret',
        );

        expect(opened?.payload).toEqual(payload);
    });

    /*
     | The compare-and-swap the server applies. It has to describe the ciphertext
     | the payload was decrypted *from*, not the one being written — the question
     | it answers is "was this row still what the client read", and digesting the
     | new value would answer nothing at all.
     */
    it('digests the ciphertext it replaces, not the one it writes', async () => {
        const crypto = await unlocked();
        const previous = toBase64(randomBytes(43));

        const sealed = await resealItem(crypto, VAULT, {
            record: { uuid: SECRET, payloadCt: previous, wrappedItemKey: '', payloadVersion: 2 },
            context: 'secret.payload',
            payload,
        });

        expect(sealed.previous_digest).toBe(toBase64(hash256(fromBase64(previous))));
        expect(sealed.previous_digest).not.toBe(toBase64(hash256(fromBase64(sealed.payload_ct))));
    });

    /*
     | A fresh Item Key every time, exactly as an ordinary write produces. Reusing
     | the old one would leave the same key wrapping the same plaintext under a
     | new envelope, which is a smaller change than the operation claims to make.
     */
    it('generates a new item key rather than rewrapping the old one', async () => {
        const crypto = await unlocked();

        const candidate: ResealCandidate<SecretPayload> = {
            record: {
                uuid: SECRET,
                payloadCt: toBase64(randomBytes(43)),
                wrappedItemKey: '',
                payloadVersion: 2,
            },
            context: 'secret.payload',
            payload,
        };

        const first = await resealItem(crypto, VAULT, candidate);
        const second = await resealItem(crypto, VAULT, candidate);

        expect(first.wrapped_item_key).not.toBe(second.wrapped_item_key);
        expect(first.payload_ct).not.toBe(second.payload_ct);
    });
});

describe('batching', () => {
    /*
     | Safe here and not for a re-key: both envelope versions open, so each row
     | is correct on its own and a batch that never arrives leaves nothing to
     | repair. That is what lets a large vault go a piece at a time.
     */
    it('splits into whole batches with a short tail', () => {
        expect(batched([1, 2, 3, 4, 5], 2)).toEqual([[1, 2], [3, 4], [5]]);
        expect(batched([1, 2], 5)).toEqual([[1, 2]]);
        expect(batched([], 5)).toEqual([]);
    });
});
