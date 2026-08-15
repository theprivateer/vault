import { describe, expect, it } from 'vitest';

import type { AadParams } from '../aad';
import { InvalidParameterError } from '../errors';
import { verifyGrant } from '../grant';
import { deriveFromPassword, generateKdfSalt, generateKey, wrapKey } from '../keys';
import { utf8ToBytes } from '../primitives';
import type { Handler, WorkerScope } from './handler';
import { createHandler, installHandler, serialiseError } from './handler';
import type { RegistrationResult } from './keyring';
import { Keyring } from './keyring';
import type { Reply, Request } from './protocol';
import { ED25519_KEY, USER_KEY, X25519_KEY } from './protocol';

const FAST_KDF = { m: 8, t: 1, p: 1 };
const SUBJECT = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f6';

const userKeyAad: AadParams = { context: 'user.userkey', subject: SUBJECT, version: 1 };
const itemAad: AadParams = { context: 'secret.payload', subject: SUBJECT, version: 1 };
const vaultKeyAad: AadParams = { context: 'item.key', subject: SUBJECT, version: 1 };

const PASSWORD = 'correct horse battery staple';

function unlockRequest() {
    const kdfSalt = generateKdfSalt();
    const userKey = generateKey();
    const { kek } = deriveFromPassword(PASSWORD, kdfSalt, FAST_KDF);

    return {
        userKey,
        request: {
            op: 'unlock',
            password: PASSWORD,
            kdfSalt,
            kdfParams: FAST_KDF,
            wrappedUserKey: wrapKey(kek, userKey, userKeyAad),
            userKeyAad,
        } satisfies Request,
    };
}

describe('dispatch', () => {
    it('reports status', () => {
        const handler = createHandler();

        expect(handler({ op: 'status' })).toEqual({ unlocked: false, handles: [] });

        handler(unlockRequest().request);

        expect(handler({ op: 'status' })).toEqual({ unlocked: true, handles: [USER_KEY] });
    });

    it('seals and opens through the protocol', () => {
        const handler = createHandler();
        handler(unlockRequest().request);

        const plaintext = utf8ToBytes('a payload');
        const { bytes } = handler({
            op: 'seal',
            handle: USER_KEY,
            plaintext,
            aad: itemAad,
        }) as { bytes: Uint8Array };

        expect(handler({ op: 'open', handle: USER_KEY, envelope: bytes, aad: itemAad })).toEqual({
            bytes: plaintext,
        });
    });

    it('unwraps into a new handle', () => {
        const handler = createHandler();
        const { userKey, request } = unlockRequest();
        handler(request);

        handler({
            op: 'unwrapInto',
            handle: 'vault',
            using: USER_KEY,
            wrapped: wrapKey(userKey, generateKey(), vaultKeyAad),
            aad: vaultKeyAad,
        });

        expect(handler({ op: 'status' })).toEqual({
            unlocked: true,
            handles: ['vault', USER_KEY].sort(),
        });
    });

    it('locks', () => {
        const handler = createHandler();
        handler(unlockRequest().request);
        handler({ op: 'lock' });

        expect(handler({ op: 'status' })).toEqual({ unlocked: false, handles: [] });
    });

    it('rejects an unknown operation', () => {
        expect(() => createHandler()({ op: 'exfiltrate' } as unknown as Request)).toThrow(
            /Unknown crypto operation/,
        );
    });
});

describe('item key operations', () => {
    /** Registers, then loads the identity private key the way a page does. */
    function identityHandler(): { handler: Handler; publicKey: Uint8Array } {
        const handler = createHandler();

        const registration = handler({
            op: 'register',
            password: PASSWORD,
            kdfSalt: generateKdfSalt(),
            kdfParams: FAST_KDF,
            uuid: SUBJECT,
        }) as RegistrationResult;

        handler({
            op: 'unwrapInto',
            handle: X25519_KEY,
            using: USER_KEY,
            wrapped: registration.x25519PrivateKeyCt,
            aad: { context: 'user.privkey.x25519', subject: SUBJECT, version: 1 },
        });

        return { handler, publicKey: registration.x25519PublicKey };
    }

    it('generates, wraps, seals and unseals through the protocol', () => {
        const { handler, publicKey } = identityHandler();

        handler({ op: 'generateInto', handle: 'vault' });
        handler({ op: 'generateInto', handle: 'item' });

        const { bytes: wrappedItemKey } = handler({
            op: 'wrapFrom',
            handle: 'item',
            using: 'vault',
            aad: vaultKeyAad,
        }) as { bytes: Uint8Array };

        const { bytes: sealedVaultKey } = handler({
            op: 'sealToPublicKey',
            handle: 'vault',
            recipientPublicKey: publicKey,
            aad: itemAad,
        }) as { bytes: Uint8Array };

        const { bytes: payload } = handler({
            op: 'seal',
            handle: 'item',
            plaintext: utf8ToBytes('secret'),
            aad: itemAad,
        }) as { bytes: Uint8Array };

        // Drop both derived keys and rebuild them from the stored blobs alone.
        handler({ op: 'forget', handle: 'vault' });
        handler({ op: 'forget', handle: 'item' });

        handler({
            op: 'openSealedInto',
            handle: 'vault',
            using: X25519_KEY,
            sealed: sealedVaultKey,
            aad: itemAad,
        });
        handler({
            op: 'unwrapInto',
            handle: 'item',
            using: 'vault',
            wrapped: wrappedItemKey,
            aad: vaultKeyAad,
        });

        expect(handler({ op: 'open', handle: 'item', envelope: payload, aad: itemAad })).toEqual({
            bytes: utf8ToBytes('secret'),
        });
    });

    it('refuses to seal the User Key to a public key', () => {
        const { handler, publicKey } = identityHandler();

        expect(() =>
            handler({
                op: 'sealToPublicKey',
                handle: USER_KEY,
                recipientPublicKey: publicKey,
                aad: itemAad,
            }),
        ).toThrow(InvalidParameterError);
    });

    it('signs a grant and returns the exact bytes it signed', () => {
        const handler = createHandler();

        const registration = handler({
            op: 'register',
            password: PASSWORD,
            kdfSalt: generateKdfSalt(),
            kdfParams: FAST_KDF,
            uuid: SUBJECT,
        }) as RegistrationResult;

        handler({
            op: 'unwrapInto',
            handle: ED25519_KEY,
            using: USER_KEY,
            wrapped: registration.ed25519PrivateKeyCt,
            aad: { context: 'user.privkey.ed25519', subject: SUBJECT, version: 1 },
        });

        const grant = {
            vaultUuid: SUBJECT,
            recipientUuid: '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5aa',
            recipientFingerprint: 'c'.repeat(64),
            role: 'viewer' as const,
            keyEpoch: 1,
            grantedAt: '2026-08-15T09:00:00Z',
        };

        const signed = handler({ op: 'signGrant', grant }) as { payload: string; signature: Uint8Array };

        expect(
            verifyGrant(signed.signature, signed.payload, registration.ed25519PublicKey, grant),
        ).toMatchObject({ valid: true });
    });
});

/*
 | The guarantee the whole Worker exists for. Injected script on the main thread
 | can ask for decryptions; it must not be able to lift the keys themselves.
 */
describe('key isolation', () => {
    it('never emits key material in any response', () => {
        const keyring = new Keyring();
        const handler = createHandler(keyring);
        const { userKey, request } = unlockRequest();

        const vaultKey = generateKey();

        const responses: unknown[] = [
            handler(request),
            handler({ op: 'status' }),
            handler({
                op: 'unwrapInto',
                handle: 'vault',
                using: USER_KEY,
                wrapped: wrapKey(userKey, vaultKey, vaultKeyAad),
                aad: vaultKeyAad,
            }),
            handler({ op: 'seal', handle: 'vault', plaintext: utf8ToBytes('secret'), aad: itemAad }),
            handler({ op: 'generateInto', handle: 'item' }),
            handler({ op: 'wrapFrom', handle: 'item', using: 'vault', aad: vaultKeyAad }),
            handler({ op: 'status' }),
            handler({ op: 'forget', handle: 'item' }),
            handler({ op: 'lock' }),
        ];

        const haystack = JSON.stringify(responses, (_key, value: unknown) =>
            value instanceof Uint8Array ? [...value] : value,
        );

        for (const [label, key] of [
            ['user key', userKey],
            ['vault key', vaultKey],
        ] as const) {
            expect(haystack, `${label} leaked in a response`).not.toContain([...key].join(','));
        }
    });

    it('exposes handles but not the keys behind them', () => {
        const handler = createHandler();
        handler(unlockRequest().request);

        const status = handler({ op: 'status' }) as { handles: string[] };

        expect(status.handles).toEqual([USER_KEY]);
        expect(status.handles.every((handle) => typeof handle === 'string')).toBe(true);
    });
});

describe('error serialisation', () => {
    it('preserves the class name so the client can reconstruct it', () => {
        const handler = createHandler();

        try {
            handler({ op: 'seal', handle: 'missing', plaintext: utf8ToBytes('x'), aad: itemAad });
            expect.unreachable('expected a KeyUnavailableError');
        } catch (cause) {
            const serialised = serialiseError(cause);

            expect(serialised.name).toBe('KeyUnavailableError');
            expect(serialised.message).toContain('missing');
        }
    });

    it('reduces an unexpected error to a generic message', () => {
        // A stray library error could carry fragments of what was being
        // processed, so only CryptoError messages are passed through.
        expect(serialiseError(new TypeError('cannot read property of 0x8f3a...'))).toEqual({
            name: 'CryptoError',
            message: 'The cryptographic operation failed.',
        });
    });

    it('handles a thrown non-error', () => {
        expect(serialiseError('a string')).toEqual({
            name: 'CryptoError',
            message: 'The cryptographic operation failed.',
        });
    });
});

describe('installHandler', () => {
    function fakeScope(handler?: Handler): { scope: WorkerScope; sent: Reply[] } {
        const sent: Reply[] = [];
        const scope: WorkerScope = {
            onmessage: null,
            postMessage: (message) => sent.push(message),
        };

        installHandler(scope, handler);

        return { scope, sent };
    }

    it('replies with the result, correlated by id', () => {
        const { scope, sent } = fakeScope();

        scope.onmessage?.({ data: { id: 7, request: { op: 'status' } } });

        expect(sent).toEqual([{ id: 7, ok: true, result: { unlocked: false, handles: [] } }]);
    });

    it('replies with a serialised error instead of throwing', () => {
        const { scope, sent } = fakeScope(() => {
            throw new TypeError('boom');
        });

        expect(() => scope.onmessage?.({ data: { id: 1, request: { op: 'status' } } })).not.toThrow();

        expect(sent).toEqual([
            {
                id: 1,
                ok: false,
                error: { name: 'CryptoError', message: 'The cryptographic operation failed.' },
            },
        ]);
    });

    it('installs a default handler when none is given', () => {
        const { scope, sent } = fakeScope();

        scope.onmessage?.({ data: { id: 2, request: { op: 'lock' } } });

        expect(sent[0]).toEqual({ id: 2, ok: true, result: {} });
    });
});
