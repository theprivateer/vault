import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { HttpError, postJson } from './http';

const originalFetch = globalThis.fetch;

function mockFetch(response: Partial<Response> & { json?: () => Promise<unknown> }) {
    const fetchMock = vi.fn(() => Promise.resolve(response));
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    return fetchMock;
}

beforeEach(() => {
    vi.stubGlobal('document', { cookie: '' });
});

afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.unstubAllGlobals();
});

describe('postJson', () => {
    it('returns the decoded body on success', async () => {
        mockFetch({ ok: true, json: () => Promise.resolve({ kdfSalt: 'abc' }) });

        await expect(postJson('/auth/kdf-params', { email: 'a@b.c' })).resolves.toEqual({
            kdfSalt: 'abc',
        });
    });

    it('sends JSON with the headers Laravel expects', async () => {
        const fetchMock = mockFetch({ ok: true, json: () => Promise.resolve({}) });

        await postJson('/login', { email: 'a@b.c' });

        const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
        const headers = init.headers as Record<string, string>;

        expect(url).toBe('/login');
        expect(init.method).toBe('POST');
        expect(headers['Content-Type']).toBe('application/json');
        expect(headers.Accept).toBe('application/json');
        // Without this, Laravel answers validation failures with a redirect
        // rather than a 422 JSON body.
        expect(headers['X-Requested-With']).toBe('XMLHttpRequest');
        expect(init.body).toBe(JSON.stringify({ email: 'a@b.c' }));
    });

    it('forwards the CSRF token from the cookie, url-decoded', async () => {
        vi.stubGlobal('document', { cookie: 'foo=bar; XSRF-TOKEN=a%2Fb%3Dc; other=1' });

        const fetchMock = mockFetch({ ok: true, json: () => Promise.resolve({}) });

        await postJson('/login', {});

        const [, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];

        expect((init.headers as Record<string, string>)['X-XSRF-TOKEN']).toBe('a/b=c');
    });

    it('sends an empty token when the cookie is absent', async () => {
        const fetchMock = mockFetch({ ok: true, json: () => Promise.resolve({}) });

        await postJson('/login', {});

        const [, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];

        expect((init.headers as Record<string, string>)['X-XSRF-TOKEN']).toBe('');
    });

    it('throws an HttpError carrying the validation errors', async () => {
        mockFetch({
            ok: false,
            status: 422,
            json: () =>
                Promise.resolve({
                    message: 'The given data was invalid.',
                    errors: { email: ['Those credentials do not match our records.'] },
                }),
        });

        const failure = await postJson('/login', {}).catch((error: unknown) => error);

        expect(failure).toBeInstanceOf(HttpError);
        expect((failure as HttpError).status).toBe(422);
        expect((failure as HttpError).first('email')).toBe('Those credentials do not match our records.');
        expect((failure as HttpError).first('missing')).toBeUndefined();
    });

    it('survives an error response with no JSON body', async () => {
        mockFetch({
            ok: false,
            status: 500,
            json: () => Promise.reject(new Error('not json')),
        });

        const failure = await postJson('/login', {}).catch((error: unknown) => error);

        expect(failure).toBeInstanceOf(HttpError);
        expect((failure as HttpError).status).toBe(500);
        expect((failure as HttpError).message).toBe('The request failed.');
        expect((failure as HttpError).errors).toEqual({});
    });
});
