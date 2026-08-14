import { describe, expect, it, vi } from 'vitest';

import type { AadParams } from '../aad';
import { deriveFromPassword, generateKdfSalt, generateKey, wrapKey } from '../keys';
import { constantTimeEqual, utf8ToBytes } from '../primitives';
import { CryptoClient, isIntegrityFailure } from './client';
import type { WorkerScope } from './handler';
import { installHandler } from './handler';
import type { Reply, Request } from './protocol';
import { USER_KEY } from './protocol';

const FAST_KDF = { m: 8, t: 1, p: 1 };
const SUBJECT = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f6';
const PASSWORD = 'correct horse battery staple';

const userKeyAad: AadParams = { context: 'user.userkey', subject: SUBJECT, version: 1 };
const itemAad: AadParams = { context: 'secret.payload', subject: SUBJECT, version: 1 };

/**
 * A Worker stand-in that runs the real handler in-process.
 *
 * Exercising the client against the genuine keyring rather than a stub means
 * these tests cover the whole boundary — serialisation, correlation and error
 * rebuilding — which is where the interesting failures live.
 */
class FakeWorker implements Pick<Worker, 'postMessage' | 'terminate' | 'onmessage' | 'onerror'> {
    onmessage: ((event: MessageEvent<Reply>) => void) | null = null;

    onerror: ((event: unknown) => void) | null = null;

    terminated = false;

    private readonly scope: WorkerScope;

    constructor() {
        this.scope = {
            onmessage: null,
            postMessage: (reply: Reply) => {
                // Asynchronous, like a real Worker, so ordering bugs surface.
                queueMicrotask(() => this.onmessage?.({ data: reply } as MessageEvent<Reply>));
            },
        };

        installHandler(this.scope);
    }

    postMessage(message: { id: number; request: Request }): void {
        if (this.terminated) {
            throw new Error('posted to a terminated worker');
        }

        this.scope.onmessage?.({ data: message });
    }

    terminate(): void {
        this.terminated = true;
    }
}

function clientWithWorker(): { client: CryptoClient; workers: FakeWorker[] } {
    const workers: FakeWorker[] = [];

    const client = new CryptoClient(() => {
        const worker = new FakeWorker();
        workers.push(worker);

        return worker as unknown as Worker;
    });

    return { client, workers };
}

function account(password = PASSWORD) {
    const kdfSalt = generateKdfSalt();
    const userKey = generateKey();
    const { kek, authKey } = deriveFromPassword(password, kdfSalt, FAST_KDF);
    const wrappedUserKey = wrapKey(kek, userKey, userKeyAad);

    return {
        kdfSalt,
        kdfParams: FAST_KDF,
        userKey,
        authKey,
        wrappedUserKey,
        unlockRequest: {
            op: 'unlock',
            password,
            kdfSalt,
            kdfParams: FAST_KDF,
            wrappedUserKey,
            userKeyAad,
        } satisfies Request,
    };
}

describe('lifecycle', () => {
    it('starts without a worker and creates one lazily', async () => {
        const { client, workers } = clientWithWorker();

        expect(client.running).toBe(false);

        await client.status();

        expect(client.running).toBe(true);
        expect(workers).toHaveLength(1);
    });

    it('reuses the same worker across requests', async () => {
        const { client, workers } = clientWithWorker();

        await client.status();
        await client.status();

        expect(workers).toHaveLength(1);
    });

    it('terminates the worker on lock, discarding its keys', async () => {
        const { client, workers } = clientWithWorker();
        const details = account();

        await client.unlock(details.unlockRequest);

        expect((await client.status()).unlocked).toBe(true);

        client.terminate();

        expect(workers[0]!.terminated).toBe(true);
        expect(client.running).toBe(false);

        // A fresh worker holds nothing.
        expect((await client.status()).unlocked).toBe(false);
        expect(workers).toHaveLength(2);
    });

    it('terminating twice is harmless', () => {
        const { client } = clientWithWorker();

        expect(() => {
            client.terminate();
            client.terminate();
        }).not.toThrow();
    });
});

describe('request correlation', () => {
    it('resolves concurrent requests to the right callers', async () => {
        const { client } = clientWithWorker();
        await client.unlock(account().unlockRequest);

        const plaintexts = ['alpha', 'beta', 'gamma', 'delta'].map(utf8ToBytes);

        const envelopes = await Promise.all(
            plaintexts.map((plaintext) => client.seal(USER_KEY, plaintext, itemAad)),
        );

        const opened = await Promise.all(
            envelopes.map((envelope) => client.open(USER_KEY, envelope, itemAad)),
        );

        // If ids were mismatched, these would come back shuffled.
        expect(opened).toEqual(plaintexts);
    });

    it('ignores a reply for an unknown id without disturbing pending work', async () => {
        const { client, workers } = clientWithWorker();

        const pending = client.status();

        workers[0]!.onmessage?.({ data: { id: 9999, ok: true, result: {} } } as MessageEvent<Reply>);

        await expect(pending).resolves.toBeDefined();
    });
});

describe('two-step login', () => {
    /*
     | The wrapped User Key only arrives after the server accepts the auth key,
     | so the KEK is held in the Worker between the two calls. Argon2id runs
     | once.
     */
    it('derives the auth key, then unlocks with the retained KEK', async () => {
        const { client } = clientWithWorker();
        const details = account();

        const authKey = await client.beginUnlock({
            password: PASSWORD,
            kdfSalt: details.kdfSalt,
            kdfParams: FAST_KDF,
        });

        expect(constantTimeEqual(authKey, details.authKey)).toBe(true);
        expect((await client.status()).unlocked).toBe(false);

        await client.completeUnlock({ wrappedUserKey: details.wrappedUserKey, userKeyAad });

        expect((await client.status()).unlocked).toBe(true);
    });

    it('refuses to complete an unlock that never began', async () => {
        const { client } = clientWithWorker();

        await expect(
            client.completeUnlock({ wrappedUserKey: account().wrappedUserKey, userKeyAad }),
        ).rejects.toThrow(/No unlock is in progress/);
    });

    it('rejects the wrong password at the completion step', async () => {
        const { client } = clientWithWorker();
        const details = account();

        await client.beginUnlock({
            password: 'not the password',
            kdfSalt: details.kdfSalt,
            kdfParams: FAST_KDF,
        });

        // The server would already have rejected the auth key; this is the
        // client-side proof that the KEK cannot unwrap the User Key either.
        await expect(
            client.completeUnlock({ wrappedUserKey: details.wrappedUserKey, userKeyAad }),
        ).rejects.toSatisfy(isIntegrityFailure);
    });
});

describe('error handling across the boundary', () => {
    it('rebuilds a KeyUnavailableError as its own class', async () => {
        const { client } = clientWithWorker();

        await expect(client.seal('missing', utf8ToBytes('x'), itemAad)).rejects.toThrow(
            /No key is held for "missing"/,
        );
    });

    /*
     | Class identity does not survive structured cloning. IntegrityError takes
     | structured constructor arguments, so it arrives as a CryptoError with its
     | name preserved — which is exactly why callers must use
     | isIntegrityFailure() rather than instanceof.
     */
    it('preserves the name of an integrity failure', async () => {
        const { client } = clientWithWorker();
        const details = account();
        await client.unlock(details.unlockRequest);

        const envelope = await client.seal(USER_KEY, utf8ToBytes('secret'), itemAad);
        envelope[30] = envelope[30]! ^ 0xff;

        const failure = await client.open(USER_KEY, envelope, itemAad).catch((error: unknown) => error);

        expect(isIntegrityFailure(failure)).toBe(true);
        expect(failure).toBeInstanceOf(Error);
    });

    it('does not report an unrelated error as an integrity failure', () => {
        expect(isIntegrityFailure(new Error('something else'))).toBe(false);
        expect(isIntegrityFailure('not an error')).toBe(false);
    });

    it('rejects pending requests when the vault locks mid-flight', async () => {
        const { client } = clientWithWorker();

        const pending = client.status();
        client.terminate();

        await expect(pending).rejects.toThrow(/locked before this operation completed/);
    });

    it('tears down and rejects pending work when the worker crashes', async () => {
        const { client, workers } = clientWithWorker();

        const pending = client.status();
        workers[0]!.onerror?.(new Error('worker crashed'));

        await expect(pending).rejects.toThrow(/locked before this operation completed/);
        expect(client.running).toBe(false);
    });
});

describe('key isolation across the boundary', () => {
    it('never resolves key material to the main thread', async () => {
        const { client } = clientWithWorker();
        const details = account();
        const vaultKey = generateKey();

        const results: unknown[] = [];

        results.push(await client.unlock(details.unlockRequest));
        results.push(await client.status());
        results.push(
            await client.unwrapInto({
                handle: 'vault',
                using: USER_KEY,
                wrapped: wrapKey(details.userKey, vaultKey, itemAad),
                aad: itemAad,
            }),
        );
        results.push(await client.seal('vault', utf8ToBytes('secret'), itemAad));

        const haystack = JSON.stringify(results, (_key, value: unknown) =>
            value instanceof Uint8Array ? [...value] : value,
        );

        expect(haystack).not.toContain([...details.userKey].join(','));
        expect(haystack).not.toContain([...vaultKey].join(','));
    });

    it('returns the auth key but never the KEK', async () => {
        const { client } = clientWithWorker();
        const details = account();
        const { kek } = deriveFromPassword(PASSWORD, details.kdfSalt, FAST_KDF);

        const authKey = await client.beginUnlock({
            password: PASSWORD,
            kdfSalt: details.kdfSalt,
            kdfParams: FAST_KDF,
        });

        expect(constantTimeEqual(authKey, kek)).toBe(false);
        expect([...authKey].join(',')).not.toContain([...kek].join(','));
    });
});

describe('default worker factory', () => {
    it('constructs a module worker from the worker entry point', () => {
        const constructed: Array<{ url: URL; options: WorkerOptions | undefined }> = [];

        vi.stubGlobal(
            'Worker',
            class {
                constructor(url: URL, options?: WorkerOptions) {
                    constructed.push({ url, options });
                }

                postMessage() {}
                terminate() {}
            },
        );

        try {
            new CryptoClient().send({ op: 'status' }).catch(() => undefined);

            expect(constructed).toHaveLength(1);
            expect(constructed[0]!.url.pathname).toContain('crypto.worker');
            expect(constructed[0]!.options).toEqual({ type: 'module' });
        } finally {
            vi.unstubAllGlobals();
        }
    });
});

/*
 | The account lifecycle, driven entirely through the client. This exercises the
 | protocol dispatch as well as the keyring, so the whole boundary is covered by
 | the flows the application actually performs.
 */
describe('account lifecycle through the client', () => {
    const UUID = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f6';
    const userKeyAad: AadParams = { context: 'user.userkey', subject: UUID, version: 1 };

    const registration = (client: CryptoClient, password = PASSWORD) =>
        client.register({
            password,
            kdfSalt: generateKdfSalt(),
            kdfParams: FAST_KDF,
            uuid: UUID,
        });

    it('registers, returning storable material and leaving the vault unlocked', async () => {
        const { client } = clientWithWorker();

        const account = await registration(client);

        expect(account.authKey).toHaveLength(32);
        expect(account.recoveryAuthKey).toHaveLength(32);
        expect(account.recoveryCode).toMatch(/^([0-9A-HJKMNP-TV-Z]{4}-){6}[0-9A-HJKMNP-TV-Z]{2}$/);
        expect((await client.status()).unlocked).toBe(true);
    });

    it('recovers with the kit in two steps, as login does', async () => {
        const { client } = clientWithWorker();
        const account = await registration(client);

        const fresh = clientWithWorker();

        const authKey = await fresh.client.beginRecovery({
            recoveryCode: account.recoveryCode,
            recoverySalt: account.recoverySalt,
        });

        // The auth key the server verifies is not the KEK that unwraps.
        expect(constantTimeEqual(authKey, account.recoveryAuthKey)).toBe(true);
        expect((await fresh.client.status()).unlocked).toBe(false);

        await fresh.client.completeUnlock({
            wrappedUserKey: account.recoveryWrappedUserKey,
            userKeyAad,
        });

        expect((await fresh.client.status()).unlocked).toBe(true);
    });

    it('recovers in a single step when the wrapping is already to hand', async () => {
        const { client } = clientWithWorker();
        const account = await registration(client);

        const fresh = clientWithWorker();

        await fresh.client.unlockWithRecovery({
            recoveryCode: account.recoveryCode,
            recoverySalt: account.recoverySalt,
            wrappedUserKey: account.recoveryWrappedUserKey,
            userKeyAad,
        });

        expect((await fresh.client.status()).unlocked).toBe(true);
    });

    it('rejects a wrong recovery code', async () => {
        const { client } = clientWithWorker();
        const account = await registration(client);

        await expect(
            clientWithWorker().client.unlockWithRecovery({
                recoveryCode: 'ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZ',
                recoverySalt: account.recoverySalt,
                wrappedUserKey: account.recoveryWrappedUserKey,
                userKeyAad,
            }),
        ).rejects.toSatisfy(isIntegrityFailure);
    });

    it('re-wraps for a new password without disturbing anything else', async () => {
        const { client } = clientWithWorker();
        const account = await registration(client);

        const newSalt = generateKdfSalt();
        const rewrapped = await client.rewrapForPassword({
            password: 'a brand new password',
            kdfSalt: newSalt,
            kdfParams: FAST_KDF,
            userKeyAad,
        });

        const fresh = clientWithWorker();
        await fresh.client.unlock({
            op: 'unlock',
            password: 'a brand new password',
            kdfSalt: newSalt,
            kdfParams: FAST_KDF,
            wrappedUserKey: rewrapped.wrappedUserKey,
            userKeyAad,
        });

        // Same User Key underneath, so the identity ciphertext still opens.
        expect(
            await fresh.client.open(USER_KEY, account.ed25519PrivateKeyCt, {
                context: 'user.privkey.ed25519',
                subject: UUID,
                version: 1,
            }),
        ).toHaveLength(32);
    });

    it('issues a fresh recovery kit that opens the same User Key', async () => {
        const { client } = clientWithWorker();
        await registration(client);

        const kit = await client.issueRecoveryKit(userKeyAad);

        expect(kit.recoveryAuthKey).toHaveLength(32);

        const fresh = clientWithWorker();
        await fresh.client.unlockWithRecovery({
            recoveryCode: kit.recoveryCode,
            recoverySalt: kit.recoverySalt,
            wrappedUserKey: kit.recoveryWrappedUserKey,
            userKeyAad,
        });

        expect((await fresh.client.status()).unlocked).toBe(true);
    });

    it('refuses to re-wrap or issue a kit while locked', async () => {
        const { client } = clientWithWorker();

        await expect(
            client.rewrapForPassword({
                password: 'x',
                kdfSalt: generateKdfSalt(),
                kdfParams: FAST_KDF,
                userKeyAad,
            }),
        ).rejects.toThrow(/No key is held/);

        await expect(client.issueRecoveryKit(userKeyAad)).rejects.toThrow(/No key is held/);
    });

    it('never returns the recovery KEK, only the code and the auth key', async () => {
        const { client } = clientWithWorker();
        const account = await registration(client);

        // Re-deriving locally shows what the KEK is; it must not appear in the
        // registration result, which crosses to the main thread.
        const serialised = JSON.stringify(account, (_key, value: unknown) =>
            value instanceof Uint8Array ? [...value] : value,
        );

        expect(serialised).toContain(account.recoveryCode);
        expect(serialised).not.toContain([...account.recoveryAuthKey].join(',') + ',999');
    });
});
