/**
 * JSON requests to endpoints that are not Inertia page visits.
 *
 * The auth flows deliberately avoid Inertia navigation: the component has to
 * stay mounted while it holds key material and, in the case of registration,
 * the recovery code the server will never see. A redirect would remount and
 * lose both.
 */
export class HttpError extends Error {
    constructor(
        readonly status: number,
        readonly errors: Record<string, string[]>,
        message: string,
    ) {
        super(message);
        this.name = 'HttpError';
    }

    /** The first message for a field, if the server rejected the request. */
    first(field: string): string | undefined {
        return this.errors[field]?.[0];
    }
}

function csrfToken(): string {
    return decodeURIComponent(document.cookie.match(/XSRF-TOKEN=([^;]+)/)?.[1] ?? '');
}

function headers(extra: Record<string, string> = {}): Record<string, string> {
    return {
        Accept: 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
        'X-XSRF-TOKEN': csrfToken(),
        ...extra,
    };
}

/** Turns a non-2xx response into an HttpError carrying the validation errors. */
async function fail(response: Response): Promise<never> {
    const payload = (await response.json().catch(() => ({}))) as {
        message?: string;
        errors?: Record<string, string[]>;
    };

    throw new HttpError(response.status, payload.errors ?? {}, payload.message ?? 'The request failed.');
}

export async function postJson<T>(url: string, body: unknown): Promise<T> {
    const response = await fetch(url, {
        method: 'POST',
        headers: headers({ 'Content-Type': 'application/json' }),
        body: JSON.stringify(body),
    });

    return response.ok ? (response.json() as Promise<T>) : fail(response);
}

export async function getJson<T>(url: string): Promise<T> {
    const response = await fetch(url, { headers: headers() });

    return response.ok ? (response.json() as Promise<T>) : fail(response);
}

/**
 * Sends one chunk of ciphertext as raw bytes.
 *
 * Not base64, unlike every other ciphertext in the API. A payload is kilobytes
 * and travels inside JSON where the 33% overhead does not matter; a file body is
 * the one thing large enough that it does, and a chunk endpoint has no other
 * fields to carry, so there is nothing JSON would be wrapping.
 */
export async function putBinary(url: string, bytes: Uint8Array): Promise<void> {
    const response = await fetch(url, {
        method: 'PUT',
        headers: headers({ 'Content-Type': 'application/octet-stream' }),
        // Copied into a Blob so a view over a larger buffer sends its own bytes
        // and not the whole buffer behind it.
        body: new Blob([bytes.slice()]),
    });

    if (!response.ok) {
        await fail(response);
    }
}

export async function getBinary(url: string): Promise<Uint8Array> {
    const response = await fetch(url, { headers: headers({ Accept: 'application/octet-stream' }) });

    return response.ok ? new Uint8Array(await response.arrayBuffer()) : fail(response);
}
