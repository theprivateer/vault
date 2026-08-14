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
import type { RegistrationResult } from './keyring';
import type { KeyHandle, Reply, Request, SerialisedError } from './protocol';

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

    async unwrapInto(request: Omit<Extract<Request, { op: 'unwrapInto' }>, 'op'>): Promise<void> {
        await this.send({ op: 'unwrapInto', ...request });
    }

    send<T>(request: Request): Promise<T> {
        const worker = this.ensure();
        const id = this.nextId++;

        return new Promise<T>((resolve, reject) => {
            this.pending.set(id, { resolve: resolve as (value: unknown) => void, reject });
            worker.postMessage({ id, request });
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
        this.worker?.terminate();
        this.worker = null;

        for (const { reject } of this.pending.values()) {
            reject(new KeyUnavailableError('The vault was locked before this operation completed.'));
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
             | Worker scripts must be same-origin with the page. Under `npm run
             | dev` Vite serves modules from its own port while Laravel serves
             | the page from another, so the Worker cannot be constructed at
             | all — which is why the Worker is built to a stable same-origin
             | path instead of being resolved through the dev server.
             */
            throw new WorkerUnavailableError(
                'The cryptographic worker could not be started. It must be served from the same ' +
                    'origin as the page, and permitted by the worker-src policy. ' +
                    'If you are developing, run `npm run build:worker`.',
                cause,
            );
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
            // A Worker that has crashed holds nothing useful, and every pending
            // caller needs to know rather than wait forever.
            this.terminate();
        };

        this.worker = worker;

        return worker;
    }
}
