/**
 * Main-thread client for the crypto Worker.
 *
 * Everything the application does with key material goes through here, and
 * nothing that comes back contains any. The Worker is created lazily and
 * terminated on lock — terminating it is the only erasure of key material that
 * a garbage-collected runtime actually guarantees.
 */
import type { AadParams } from '../aad';
import {
    CryptoError,
    InvalidParameterError,
    KeyUnavailableError,
    MalformedEnvelopeError,
    WorkerUnavailableError,
} from '../errors';
import type { AuditStatement, SignedStatement } from '../audit';
import type { Grant, SignedGrant } from '../grant';
import type { RegistrationResult } from './keyring';
import type { BulkOpenItem, BulkOpenResult, KeyHandle, Reply, Request, SerialisedError } from './protocol';

/** A bulk open result, with its error rebuilt into a real class. */
export type OpenedBytes = { ok: true; bytes: Uint8Array } | { ok: false; error: CryptoError };

/** Injectable so tests can supply a fake in place of a real Worker. */
export type WorkerFactory = () => Worker;

/**
 * A stable, same-origin path rather than a URL resolved through Vite.
 *
 * Worker scripts must be same-origin with the page. In development Vite serves
 * modules from its own port while Laravel serves the page from another, so
 * `new URL('./crypto.worker.ts', import.meta.url)` yields a cross-origin URL
 * the browser refuses to construct a Worker from. Building the Worker to a
 * fixed path (see vite.worker.config.ts) makes development and production
 * behave identically and keeps `worker-src 'self'` intact.
 */
export const WORKER_URL = '/build/crypto.worker.js';

const defaultFactory: WorkerFactory = () => new Worker(WORKER_URL, { type: 'module' });

/**
 * Said the same way whether the Worker refuses to construct or dies on load,
 * because from the outside those are the same problem with the same causes.
 *
 * The `child-src` note is not padding: WebKit does not implement `worker-src`,
 * so a policy that names only `worker-src` falls through to `default-src` and
 * silently blocks every Worker in Safari.
 */
export const WORKER_FAILURE_MESSAGE =
    'The cryptographic worker could not be started, so nothing can be encrypted or decrypted. ' +
    'It must be served from the same origin as the page and allowed by the Content-Security-Policy ' +
    '— note that Safari honours child-src rather than worker-src. ' +
    'If you are developing, run `npm run build:worker`.';

/**
 * Errors whose constructors take a single message, so they can be rebuilt
 * faithfully on this side of the boundary.
 */
const REBUILDABLE = {
    CryptoError,
    InvalidParameterError,
    KeyUnavailableError,
    MalformedEnvelopeError,
} as const;

/**
 * Class identity does not survive structured cloning, so errors cross as
 * `{name, message}` and are rebuilt here.
 *
 * `IntegrityError` and `UnsupportedEnvelopeError` take structured constructor
 * arguments rather than a message, so they come back as a `CryptoError` whose
 * `name` is preserved. Use `isIntegrityFailure()` rather than `instanceof` for
 * anything that crossed the boundary.
 */
function rebuildError({ name, message }: SerialisedError): CryptoError {
    const Constructor = REBUILDABLE[name as keyof typeof REBUILDABLE] ?? CryptoError;
    const error = new Constructor(message);

    error.name = name;

    return error;
}

/** True when a failure means "this data did not verify", however it was rebuilt. */
export function isIntegrityFailure(error: unknown): boolean {
    return error instanceof Error && error.name === 'IntegrityError';
}

/**
 * Rebuilds a value as plain data that `postMessage` can structured-clone.
 *
 * **Why this exists.** Requests are assembled in the application layer, where
 * some of their parts come from framework state — Inertia page props are made
 * reactive by Vue, which means they are `Proxy` objects. A Proxy has none of
 * the internal slots the structured clone algorithm needs, so posting one
 * throws `DataCloneError` and the whole operation fails at the boundary with a
 * message that says nothing about proxies. Reading each property through the
 * proxy and rebuilding a plain object is what makes the value cloneable again.
 *
 * Doing it here rather than at each call site is deliberate: the crypto core
 * cannot import Vue (nor should it), and a rule that every caller must remember
 * to unwrap its props is a rule that will be forgotten. This is also why it is
 * framework-agnostic — it reads through *any* wrapper rather than knowing about
 * one.
 *
 * Typed arrays pass through untouched. They are the one thing structured clone
 * already handles natively, this codebase only ever creates them directly, and
 * copying every payload buffer on every seal would be a real cost for no gain.
 * A wrapped typed array would therefore not be normalised — so rather than
 * silently mangling it into an object of numeric keys, anything unrecognised
 * throws by name.
 */
export function toCloneable<T>(value: T): T {
    if (value === null || typeof value !== 'object') {
        return value;
    }

    // Survives proxying: both check internal state the proxy forwards.
    if (ArrayBuffer.isView(value) || value instanceof ArrayBuffer) {
        return value;
    }

    if (Array.isArray(value)) {
        return value.map((entry: unknown) => toCloneable(entry)) as T;
    }

    const prototype: unknown = Object.getPrototypeOf(value);

    if (prototype !== Object.prototype && prototype !== null) {
        throw new InvalidParameterError(
            `Cannot send a ${(value as object).constructor?.name ?? 'non-plain'} value to the ` +
                'cryptographic worker. Only plain objects, arrays and typed arrays can cross ' +
                'the boundary.',
        );
    }

    return Object.fromEntries(
        Object.entries(value as Record<string, unknown>).map(([key, entry]) => [key, toCloneable(entry)]),
    ) as T;
}

export class CryptoClient {
    private worker: Worker | null = null;

    private nextId = 1;

    private readonly pending = new Map<
        number,
        { resolve: (value: unknown) => void; reject: (reason: CryptoError) => void }
    >();

    constructor(private readonly factory: WorkerFactory = defaultFactory) {}

    get running(): boolean {
        return this.worker !== null;
    }

    async unlock(request: Extract<Request, { op: 'unlock' }>): Promise<void> {
        await this.send(request);
    }

    /**
     * Step one of login: derives from the password and returns only the auth
     * key. The KEK stays inside the Worker for `completeUnlock`.
     */
    async beginUnlock(request: Omit<Extract<Request, { op: 'beginUnlock' }>, 'op'>): Promise<Uint8Array> {
        const { authKey } = await this.send<{ authKey: Uint8Array }>({ op: 'beginUnlock', ...request });

        return authKey;
    }

    async completeUnlock(request: Omit<Extract<Request, { op: 'completeUnlock' }>, 'op'>): Promise<void> {
        await this.send({ op: 'completeUnlock', ...request });
    }

    /** Creates an account. Leaves the vault unlocked. */
    async register(request: Omit<Extract<Request, { op: 'register' }>, 'op'>): Promise<RegistrationResult> {
        return this.send<RegistrationResult>({ op: 'register', ...request });
    }

    /** Step one of recovery: returns the auth key, retains the recovery KEK. */
    async beginRecovery(request: Omit<Extract<Request, { op: 'beginRecovery' }>, 'op'>): Promise<Uint8Array> {
        const { authKey } = await this.send<{ authKey: Uint8Array }>({ op: 'beginRecovery', ...request });

        return authKey;
    }

    async unlockWithRecovery(
        request: Omit<Extract<Request, { op: 'unlockWithRecovery' }>, 'op'>,
    ): Promise<void> {
        await this.send({ op: 'unlockWithRecovery', ...request });
    }

    async rewrapForPassword(
        request: Omit<Extract<Request, { op: 'rewrapForPassword' }>, 'op'>,
    ): Promise<{ authKey: Uint8Array; wrappedUserKey: Uint8Array }> {
        return this.send({ op: 'rewrapForPassword', ...request });
    }

    async issueRecoveryKit(userKeyAad: Extract<Request, { op: 'issueRecoveryKit' }>['userKeyAad']): Promise<{
        recoveryCode: string;
        recoverySalt: Uint8Array;
        recoveryWrappedUserKey: Uint8Array;
        recoveryAuthKey: Uint8Array;
    }> {
        return this.send({ op: 'issueRecoveryKit', userKeyAad });
    }

    async status(): Promise<{ unlocked: boolean; handles: KeyHandle[] }> {
        return this.send<{ unlocked: boolean; handles: KeyHandle[] }>({ op: 'status' });
    }

    async seal(handle: KeyHandle, plaintext: Uint8Array, aad: AadParams): Promise<Uint8Array> {
        const { bytes } = await this.send<{ bytes: Uint8Array }>({ op: 'seal', handle, plaintext, aad });

        return bytes;
    }

    async open(handle: KeyHandle, envelope: Uint8Array, aad: AadParams): Promise<Uint8Array> {
        const { bytes } = await this.send<{ bytes: Uint8Array }>({ op: 'open', handle, envelope, aad });

        return bytes;
    }

    /**
     * Opens a batch of items in one crossing of the Worker boundary.
     *
     * Errors are rebuilt into real `CryptoError` instances here rather than
     * left as the wire's `{name, message}`, so a caller can use
     * `isIntegrityFailure` on a bulk result exactly as it would on a single
     * one. Batching must not change how a failure is recognised.
     */
    async openMany(items: readonly BulkOpenItem[]): Promise<OpenedBytes[]> {
        const { results } = await this.send<{ results: BulkOpenResult[] }>({
            op: 'openMany',
            items: [...items],
        });

        return results.map((result) =>
            result.ok ? result : { ok: false as const, error: rebuildError(result.error) },
        );
    }

    /**
     * Encrypts one chunk of a file.
     *
     * One crossing per chunk, unlike `openMany`. Batching would not help: a
     * chunk is a mebibyte, so the structured clone dwarfs the message overhead
     * either way, and holding several in flight is what a caller should do to
     * fill the pipe rather than something this should decide for them.
     */
    async sealChunk(request: Omit<Extract<Request, { op: 'sealChunk' }>, 'op'>): Promise<Uint8Array> {
        const { bytes } = await this.send<{ bytes: Uint8Array }>({ op: 'sealChunk', ...request });

        return bytes;
    }

    async openChunk(request: Omit<Extract<Request, { op: 'openChunk' }>, 'op'>): Promise<Uint8Array> {
        const { bytes } = await this.send<{ bytes: Uint8Array }>({ op: 'openChunk', ...request });

        return bytes;
    }

    async unwrapInto(request: Omit<Extract<Request, { op: 'unwrapInto' }>, 'op'>): Promise<void> {
        await this.send({ op: 'unwrapInto', ...request });
    }

    async generateInto(handle: KeyHandle): Promise<void> {
        await this.send({ op: 'generateInto', handle });
    }

    async wrapFrom(handle: KeyHandle, using: KeyHandle, aad: AadParams): Promise<Uint8Array> {
        const { bytes } = await this.send<{ bytes: Uint8Array }>({ op: 'wrapFrom', handle, using, aad });

        return bytes;
    }

    async sealToPublicKey(
        handle: KeyHandle,
        recipientPublicKey: Uint8Array,
        aad: AadParams,
    ): Promise<Uint8Array> {
        const { bytes } = await this.send<{ bytes: Uint8Array }>({
            op: 'sealToPublicKey',
            handle,
            recipientPublicKey,
            aad,
        });

        return bytes;
    }

    async openSealedInto(request: Omit<Extract<Request, { op: 'openSealedInto' }>, 'op'>): Promise<void> {
        await this.send({ op: 'openSealedInto', ...request });
    }

    /**
     * Signs a membership grant, returning the exact bytes that were signed.
     *
     * The payload comes back rather than being rebuilt by the caller because it
     * is what gets stored: a signature verifies against those bytes and no
     * others, so re-serialising them anywhere else is a chance for the two to
     * drift apart.
     */
    async signGrant(grant: Grant): Promise<SignedGrant> {
        return this.send<SignedGrant>({ op: 'signGrant', grant });
    }

    /**
     * Signs a statement about something only this tab observed.
     *
     * The payload comes back rather than being rebuilt by the caller, for the
     * reason `signGrant` returns one: it is what gets stored, a signature
     * verifies against those bytes and no others, and re-serialising them
     * anywhere else is a chance for the two to drift apart.
     */
    async signAuditStatement(statement: AuditStatement): Promise<SignedStatement> {
        return this.send<SignedStatement>({ op: 'signAuditStatement', statement });
    }

    async forget(handle: KeyHandle): Promise<void> {
        await this.send({ op: 'forget', handle });
    }

    send<T>(request: Request): Promise<T> {
        const worker = this.ensure();
        const id = this.nextId++;

        return new Promise<T>((resolve, reject) => {
            this.pending.set(id, { resolve: resolve as (value: unknown) => void, reject });

            // Normalised first: postMessage structured-clones its argument, and
            // a framework's reactive wrapper is not cloneable. See toCloneable.
            worker.postMessage({ id, request: toCloneable(request) });
        });
    }

    /**
     * Terminates the Worker, discarding every key it held.
     *
     * Pending requests are rejected rather than left hanging: a caller awaiting
     * a decrypt when the vault locks should see a failure, not a promise that
     * never settles.
     */
    terminate(): void {
        this.discard(new KeyUnavailableError('The vault was locked before this operation completed.'));
    }

    /**
     * Tears the Worker down, rejecting everything still in flight with a stated
     * reason.
     *
     * The reason matters. A Worker that failed to start and a vault that was
     * deliberately locked both leave callers with an unfulfilled promise, and
     * reporting the second when it was the first sends whoever is debugging in
     * precisely the wrong direction.
     */
    private discard(reason: CryptoError): void {
        this.worker?.terminate();
        this.worker = null;

        for (const { reject } of this.pending.values()) {
            reject(reason);
        }

        this.pending.clear();
    }

    private ensure(): Worker {
        if (this.worker) {
            return this.worker;
        }

        let worker: Worker;

        try {
            worker = this.factory();
        } catch (cause) {
            /*
             | Two causes reach here, and both are environmental rather than
             | cryptographic:
             |
             |   - Cross-origin. Worker scripts must be same-origin with the
             |     page, and under `npm run dev` Vite serves modules from its
             |     own port while Laravel serves the page from another. Hence
             |     the Worker being built to a stable same-origin path rather
             |     than resolved through the dev server.
             |   - Blocked by the CSP, which in Safari means `child-src` rather
             |     than `worker-src`. Browsers differ on whether that throws
             |     here or fires onerror later, so both paths report it.
             */
            throw new WorkerUnavailableError(WORKER_FAILURE_MESSAGE, cause);
        }

        worker.onmessage = ({ data }: MessageEvent<Reply>) => {
            const entry = this.pending.get(data.id);

            if (!entry) {
                return;
            }

            this.pending.delete(data.id);

            if (data.ok) {
                entry.resolve(data.result);
            } else {
                entry.reject(rebuildError(data.error));
            }
        };

        worker.onerror = () => {
            /*
             | A Worker that has crashed holds nothing useful, and every pending
             | caller needs to know rather than wait forever.
             |
             | This is also where a Worker *blocked by the CSP* surfaces in
             | browsers that refuse it asynchronously rather than throwing from
             | the constructor, so the message names that case explicitly.
             */
            this.discard(new WorkerUnavailableError(WORKER_FAILURE_MESSAGE));
        };

        this.worker = worker;

        return worker;
    }
}
