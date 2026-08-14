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

export async function postJson<T>(url: string, body: unknown): Promise<T> {
    const response = await fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            Accept: 'application/json',
            'X-Requested-With': 'XMLHttpRequest',
            'X-XSRF-TOKEN': csrfToken(),
        },
        body: JSON.stringify(body),
    });

    if (response.ok) {
        return response.json() as Promise<T>;
    }

    const payload = (await response.json().catch(() => ({}))) as {
        message?: string;
        errors?: Record<string, string[]>;
    };

    throw new HttpError(response.status, payload.errors ?? {}, payload.message ?? 'The request failed.');
}
