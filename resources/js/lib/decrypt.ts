/**
 * Decrypting a page's worth of records, and reporting what could not be read.
 *
 * The rule that shapes this module: **a failure is a state, never an absence.**
 * An item whose tag does not verify comes back with an `error` and no payload,
 * and the interface has to render that error. The 2017 application caught the
 * decryption exception and returned null, so a tampered secret looked exactly
 * like an empty one — the specific bug this project exists to correct (SR3).
 */
import { ref, type Ref } from 'vue';

import type { AadContext } from '@/crypto/aad';
import { CryptoError } from '@/crypto/errors';
import type { CryptoClient } from '@/crypto/worker/client';
import { isIntegrityFailure } from '@/crypto/worker/client';

import type { EncryptedItem, VaultRecord } from './items';
import { openItem, openVaultKey } from './items';

export interface Opened<R, P> {
    record: R;
    payload: P | null;
    /** Non-null exactly when `payload` is null. Must be shown, not swallowed. */
    error: string | null;
}

/** The message a user sees when a record does not verify. */
export function describeFailure(error: unknown, label: string): string {
    if (isIntegrityFailure(error)) {
        return `${label} could not be verified. It may have been altered in storage, or encrypted for a different record.`;
    }

    if (error instanceof CryptoError) {
        return error.message;
    }

    return `${label} could not be decrypted.`;
}

/**
 * Decrypts a list, isolating failures to the item that failed.
 *
 * One unreadable secret must not blank out the twenty beside it — a vault where
 * a single bad row hides everything is a vault people stop trusting for the
 * wrong reason.
 */
export async function openAll<R extends EncryptedItem, P>(
    client: CryptoClient,
    vaultUuid: string,
    context: AadContext,
    records: readonly R[],
    label: (record: R) => string,
): Promise<Array<Opened<R, P>>> {
    const opened: Array<Opened<R, P>> = [];

    for (const record of records) {
        try {
            opened.push({
                record,
                payload: await openItem<P>(client, vaultUuid, context, record),
                error: null,
            });
        } catch (error) {
            opened.push({ record, payload: null, error: describeFailure(error, label(record)) });
        }
    }

    return opened;
}

/**
 * Opens a vault's key, then decrypts its own payload.
 *
 * Failure here is different in kind from a single bad item: without the Vault
 * Key nothing below it can be read, so it is reported as a page-level error
 * rather than a row-level one.
 */
export async function openVault<P>(
    client: CryptoClient,
    vault: VaultRecord,
): Promise<Opened<VaultRecord, P>> {
    try {
        await openVaultKey(client, vault);

        return {
            record: vault,
            payload: await openItem<P>(client, vault.uuid, 'vault.payload', vault),
            error: null,
        };
    } catch (error) {
        return { record: vault, payload: null, error: describeFailure(error, 'This vault') };
    }
}

/**
 * Wraps an async decryption run with its own busy and failure state.
 *
 * Every page here does the same three things — clear the error, do the work,
 * report what went wrong — and doing them by hand each time is how one of them
 * ends up quietly swallowing an exception.
 */
export function useDecryption(): {
    busy: Ref<boolean>;
    failure: Ref<string>;
    run: (work: () => Promise<void>) => Promise<void>;
} {
    const busy = ref(false);
    const failure = ref('');

    async function run(work: () => Promise<void>): Promise<void> {
        busy.value = true;
        failure.value = '';

        try {
            await work();
        } catch (error) {
            failure.value = describeFailure(error, 'This page');
        } finally {
            busy.value = false;
        }
    }

    return { busy, failure, run };
}
