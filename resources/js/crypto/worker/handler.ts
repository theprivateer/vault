/**
 * Dispatches protocol requests against a keyring, and installs the handler on a
 * Worker scope.
 *
 * `installHandler` takes the scope as an argument rather than reaching for the
 * global `self`, so the glue is exercised by tests with a fake scope instead of
 * being an untested gap between the Worker and the logic.
 */
import { CryptoError, InvalidParameterError } from '../errors';
import { Keyring } from './keyring';
import type { Reply, Request, SerialisedError } from './protocol';

/**
 * Most operations answer synchronously; the file-chunk pair does not, because
 * WebCrypto is promise-based. The return type covers both rather than making
 * every caller await a value that was already there.
 */
export type Handler = (request: Request) => unknown;

export function createHandler(keyring: Keyring = new Keyring()): Handler {
    return (request: Request): unknown => {
        switch (request.op) {
            case 'unlock':
                keyring.unlock(request);

                return {};

            case 'beginUnlock':
                return {
                    authKey: keyring.beginUnlock(request.password, request.kdfSalt, request.kdfParams),
                };

            case 'completeUnlock':
                keyring.completeUnlock(request.wrappedUserKey, request.userKeyAad);

                return {};

            case 'register':
                return keyring.register(request);

            case 'beginRecovery':
                return { authKey: keyring.beginRecovery(request.recoveryCode, request.recoverySalt) };

            case 'unlockWithRecovery':
                keyring.unlockWithRecovery(
                    request.recoveryCode,
                    request.recoverySalt,
                    request.wrappedUserKey,
                    request.userKeyAad,
                );

                return {};

            case 'rewrapForPassword':
                return keyring.rewrapForPassword(
                    request.password,
                    request.kdfSalt,
                    request.kdfParams,
                    request.userKeyAad,
                );

            case 'issueRecoveryKit':
                return keyring.issueRecoveryKit(request.userKeyAad);

            case 'rotateIdentity':
                return keyring.rotateIdentity({
                    uuid: request.uuid,
                    rotatedAt: request.rotatedAt,
                    memberships: request.memberships,
                });

            case 'lock':
                keyring.lock();

                return {};

            case 'status':
                return { unlocked: keyring.unlocked, handles: keyring.handles };

            case 'seal':
                return { bytes: keyring.seal(request.handle, request.plaintext, request.aad) };

            case 'open':
                return { bytes: keyring.open(request.handle, request.envelope, request.aad) };

            case 'openMany':
                /*
                 | Failures are caught per item and returned rather than
                 | thrown, so a batch reports exactly what a sequence of single
                 | opens would have. If one bad row could reject the request,
                 | the number of readable secrets on a page would depend on
                 | which batch the bad one landed in.
                 */
                return {
                    results: request.items.map((item) => {
                        try {
                            return { ok: true as const, bytes: keyring.openWithWrappedKey(item) };
                        } catch (cause) {
                            return { ok: false as const, error: serialiseError(cause) };
                        }
                    }),
                };

            /*
             | The two asynchronous cases. `installHandler` awaits whatever
             | comes back, so a rejection here is reported exactly as a throw
             | from any other op would be — an integrity failure on chunk 40 of
             | a download must not arrive as an unhandled rejection.
             */
            case 'sealChunk':
                return keyring.sealChunk(request).then((bytes) => ({ bytes }));

            case 'openChunk':
                return keyring.openChunk(request).then((bytes) => ({ bytes }));

            case 'unwrapInto':
                keyring.unwrapInto(request.handle, request.using, request.wrapped, request.aad);

                return {};

            case 'generateInto':
                keyring.generateInto(request.handle);

                return {};

            case 'wrapFrom':
                return { bytes: keyring.wrapFrom(request.handle, request.using, request.aad) };

            case 'sealToPublicKey':
                return {
                    bytes: keyring.sealToPublicKey(request.handle, request.recipientPublicKey, request.aad),
                };

            case 'openSealedInto':
                keyring.openSealedInto(request.handle, request.using, request.sealed, request.aad);

                return {};

            case 'signGrant':
                return keyring.signGrant(request.grant);

            case 'signAuditStatement':
                return keyring.signAuditStatement(request.statement);

            case 'forget':
                keyring.forget(request.handle);

                return {};

            default:
                // Exhaustiveness: adding a Request variant without handling it
                // is a compile error, and an unrecognised op at runtime is
                // rejected rather than ignored.
                throw new InvalidParameterError(
                    `Unknown crypto operation: ${String((request as { op: unknown }).op)}`,
                );
        }
    };
}

export function serialiseError(cause: unknown): SerialisedError {
    if (cause instanceof CryptoError) {
        return { name: cause.name, message: cause.message };
    }

    /*
     | Anything else is unexpected, and its message could contain fragments of
     | whatever was being processed. Reporting a generic failure keeps a stray
     | library error from becoming a disclosure channel.
     */
    return { name: 'CryptoError', message: 'The cryptographic operation failed.' };
}

/** The minimum surface of a Worker global that the handler needs. */
export interface WorkerScope {
    onmessage: ((event: { data: { id: number; request: Request } }) => void) | null;
    postMessage(message: Reply): void;
}

/**
 * Installs the handler and replies to every message, however it settled.
 *
 * The result is awaited because the file-chunk operations return promises. A
 * synchronous op still resolves in a microtask, and microtasks run in order, so
 * replies keep arriving in the order the requests did — the client correlates
 * by id in any case, but a reordering here would be a nasty thing to discover.
 */
export function installHandler(scope: WorkerScope, handler: Handler = createHandler()): void {
    scope.onmessage = ({ data: { id, request } }) => {
        void (async () => {
            try {
                scope.postMessage({ id, ok: true, result: await handler(request) });
            } catch (cause) {
                scope.postMessage({ id, ok: false, error: serialiseError(cause) });
            }
        })();
    };
}
