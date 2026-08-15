/**
 * Which half of a share link's credential goes over the wire, and when.
 *
 * This module is small and its correctness is entirely about that question, so
 * that is what these tests assert. Getting it backwards is a one-word change
 * with a serious consequence in each direction:
 *
 *  - Posting the **token** at creation would hand the server a redeemable
 *    credential it has no need for.
 *  - Posting the **hash** at redemption would make the stored value the thing
 *    that opens a link, so anyone who could read the database could open every
 *    outstanding share — defeating the entire point of storing a hash.
 *
 * And the link key must appear in neither. It exists only in a URL fragment.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { generateLinkCredentials, sealLink, tokenHash } from '@/crypto/sharelink';

import { toBase64 } from './bytes';
import { PAYLOAD_VERSION, type SecretPayload } from './items';
import { createShareLink, revealShareLink } from './sharelink';

const originalFetch = globalThis.fetch;

function mockFetch(body: unknown = {}) {
    const fetchMock = vi.fn(() => Promise.resolve({ ok: true, json: () => Promise.resolve(body) }));
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    return fetchMock;
}

/** The body of the single request a call made. */
function sentBody(fetchMock: ReturnType<typeof mockFetch>): Record<string, unknown> {
    // Typed as the string `postJson` actually sends, rather than RequestInit's
    // BodyInit union — stringifying that union is what ESLint objects to, and
    // rightly: a Blob would stringify to "[object Object]" and pass silently.
    const [, init] = fetchMock.mock.calls[0] as unknown as [string, { body: string }];

    return JSON.parse(init.body) as Record<string, unknown>;
}

const payload: SecretPayload = {
    type: 'password',
    key: 'Router',
    value: 'hunter2',
    notes: '',
};

beforeEach(() => {
    vi.stubGlobal('document', { cookie: '' });
});

afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.unstubAllGlobals();
});

describe('creating a link', () => {
    it('sends the token’s hash and never the token or the key', async () => {
        const fetchMock = mockFetch();
        const credentials = generateLinkCredentials();

        await createShareLink(
            '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5fa',
            payload,
            {
                expiresInHours: 24,
                maxViews: 1,
            },
            credentials,
        );

        const body = sentBody(fetchMock);
        const wire = JSON.stringify(body);

        expect(body.token_hash).toBe(toBase64(tokenHash(credentials.token)));
        expect(wire).not.toContain(toBase64(credentials.token));
        expect(wire).not.toContain(toBase64(credentials.key));
    });

    it('posts to the secret’s own endpoint with a fresh identifier', async () => {
        const fetchMock = mockFetch();
        const uuid = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5fa';

        const first = await createShareLink(
            uuid,
            payload,
            { expiresInHours: 1, maxViews: 1 },
            generateLinkCredentials(),
        );
        const second = await createShareLink(
            uuid,
            payload,
            { expiresInHours: 1, maxViews: 1 },
            generateLinkCredentials(),
        );

        const [url] = fetchMock.mock.calls[0] as unknown as [string];

        expect(url).toBe(`/secrets/${uuid}/links`);
        expect(first.uuid).not.toBe(second.uuid);
    });

    /*
     | Padded to a bucket like a stored item, so a share does not publish the
     | length of the credential it carries. Easy to miss: this path does not go
     | through `sealItem`, which is where the padding normally lives.
     |
     | Bucketed rather than one fixed size, so what this asserts is that two
     | values *within* a bucket are indistinguishable — a one-character password
     | and a five-character one. Two payloads far enough apart still land in
     | different buckets, and that residual leak is written down in
     | docs/02-threat-model.md rather than claimed away here.
     */
    it('pads the payload, so two short secrets are the same size on the wire', async () => {
        const lengths: number[] = [];

        for (const value of ['a', 'aaaaa']) {
            globalThis.fetch = originalFetch;
            const fetchMock = mockFetch();

            await createShareLink(
                '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5fa',
                { ...payload, value },
                { expiresInHours: 1, maxViews: 1 },
                generateLinkCredentials(),
            );

            lengths.push(String(sentBody(fetchMock).payload_ct).length);
        }

        expect(lengths[0]).toBe(lengths[1]);
    });
});

describe('opening a link', () => {
    it('sends the token itself, url-safe, and never the key', async () => {
        const credentials = generateLinkCredentials();
        const sealed = sealLink(credentials, new TextEncoder().encode('{}'), PAYLOAD_VERSION);

        const fetchMock = mockFetch({
            payloadCt: toBase64(sealed),
            payloadVersion: PAYLOAD_VERSION,
            viewsRemaining: 0,
        });

        await revealShareLink(credentials).catch(() => undefined);

        const body = sentBody(fetchMock);

        expect(String(body.token)).toMatch(/^[A-Za-z0-9_-]{43}$/);
        expect(body.token_hash).toBeUndefined();
        expect(JSON.stringify(body)).not.toContain(toBase64(credentials.key));
    });

    it('decrypts what comes back and reports the views left', async () => {
        const credentials = generateLinkCredentials();

        // Sealed exactly as `createShareLink` would, so this is a real round
        // trip rather than a decryption of something this test made up.
        const fetchMock = mockFetch();

        await createShareLink(
            '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5fa',
            payload,
            { expiresInHours: 1, maxViews: 2 },
            credentials,
        );

        const stored = String(sentBody(fetchMock).payload_ct);

        globalThis.fetch = originalFetch;
        mockFetch({ payloadCt: stored, payloadVersion: PAYLOAD_VERSION, viewsRemaining: 1 });

        await expect(revealShareLink(credentials)).resolves.toEqual({
            payload,
            viewsRemaining: 1,
        });
    });

    it('fails loudly when the payload does not verify', async () => {
        const credentials = generateLinkCredentials();
        const sealed = sealLink(credentials, new TextEncoder().encode('{}'), PAYLOAD_VERSION);

        sealed[sealed.length - 1]! ^= 0x01;

        mockFetch({
            payloadCt: toBase64(sealed),
            payloadVersion: PAYLOAD_VERSION,
            viewsRemaining: 0,
        });

        // Never a blank box. A recipient shown nothing cannot tell "tampered
        // with" from "the sender sent nothing".
        await expect(revealShareLink(credentials)).rejects.toThrow();
    });
});
