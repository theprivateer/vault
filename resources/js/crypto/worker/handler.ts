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

export function installHandler(scope: WorkerScope, handler: Handler = createHandler()): void {
    scope.onmessage = ({ data: { id, request } }) => {
        try {
            scope.postMessage({ id, ok: true, result: handler(request) });
        } catch (cause) {
            scope.postMessage({ id, ok: false, error: serialiseError(cause) });
        }
    };
}
