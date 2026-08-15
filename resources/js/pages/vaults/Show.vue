<script setup lang="ts">
/**
 * One vault: its lockboxes, and every secret in it decrypted into the store.
 *
 * The whole vault arrives as ciphertext and is opened here, rather than a page
 * at a time, because search is the client's problem (D5) and a client cannot
 * search what it has not decrypted. That is a real cost, so it is measured
 * rather than assumed — see the scale ceiling in docs/06-testing-and-ci.md —
 * and it is shown to the user as progress rather than hidden behind a spinner.
 */
import { Head, Link, router } from '@inertiajs/vue3';
import { computed, ref, watch } from 'vue';

import NoticePanel from '@/components/NoticePanel.vue';
import TextField from '@/components/TextField.vue';
import AppLayout from '@/layouts/AppLayout.vue';
import { describeError } from '@/lib/errors';
import { sealItem, type LockboxRecord, type SecretRecord, type VaultRecord } from '@/lib/items';
import { uuid7 } from '@/lib/uuid';
import { useSession } from '@/stores/session';
import { useVaultContents } from '@/stores/vault';

const props = defineProps<{
    vault: VaultRecord;
    lockboxes: LockboxRecord[];
    secrets: SecretRecord[];
}>();

const { isUnlocked, crypto } = useSession();
const { contents, busy, failure, progress, showProgress, openContents, secretsIn } = useVaultContents();

const creating = ref(false);
const name = ref('');
const description = ref('');
const createFailure = ref('');

const canWrite = computed(() => props.vault.membership.role !== 'viewer');

const openedLockboxes = computed(() => contents.value.lockboxes);
const percent = computed(() =>
    progress.value.total === 0 ? 0 : Math.round((progress.value.done / progress.value.total) * 100),
);

/**
 * Re-runs whenever the ciphertext changes or the vault is unlocked, because
 * both are reasons the plaintext on screen is no longer correct. The store
 * re-decrypts only the records whose ciphertext actually moved.
 */
watch(
    [() => props.vault, () => props.lockboxes, () => props.secrets, isUnlocked],
    async () => {
        if (!isUnlocked.value) {
            return;
        }

        await openContents(crypto(), {
            vault: props.vault,
            lockboxes: props.lockboxes,
            secrets: props.secrets,
        });
    },
    { immediate: true },
);

async function create(): Promise<void> {
    createFailure.value = '';

    let sealed;
    const uuid = uuid7();

    try {
        sealed = await sealItem(crypto(), props.vault.uuid, 'lockbox.payload', uuid, {
            name: name.value,
            description: description.value,
        });
    } catch (error) {
        createFailure.value = describeError(error, 'The lockbox could not be encrypted.');

        return;
    }

    router.post(
        `/vaults/${props.vault.uuid}/lockboxes`,
        { uuid, ...sealed, sort_order: props.lockboxes.length },
        {
            onSuccess: () => {
                name.value = '';
                description.value = '';
                creating.value = false;
            },
            onError: (errors) => {
                createFailure.value = Object.values(errors)[0] ?? 'The lockbox could not be saved.';
            },
        },
    );
}

function destroy(): void {
    router.delete(`/vaults/${props.vault.uuid}`);
}
</script>

<template>
    <AppLayout>
        <Head :title="contents.vault?.payload?.name ?? 'Vault'" />

        <Link href="/vaults" class="text-2xs text-muted hover:text-ink">&larr; all vaults</Link>

        <NoticePanel v-if="failure" tone="accent" heading="this vault could not be opened" class="mt-4">
            {{ failure }}
        </NoticePanel>

        <div v-else class="mt-4 flex items-baseline justify-between gap-4">
            <div>
                <h1 class="text-base font-medium">{{ contents.vault?.payload?.name ?? '—' }}</h1>
                <p v-if="contents.vault?.payload?.description" class="mt-1 text-sm text-muted">
                    {{ contents.vault.payload.description }}
                </p>
                <p class="mt-1 text-2xs text-faint">
                    {{ contents.secrets.length }}
                    {{ contents.secrets.length === 1 ? 'secret' : 'secrets' }} decrypted in this browser
                    &middot; press <kbd class="text-ink">/</kbd> to search without touching the network
                </p>
            </div>

            <div class="flex items-center gap-4">
                <button v-if="canWrite" type="button" class="btn" @click="creating = !creating">
                    {{ creating ? 'cancel' : 'new lockbox' }}
                </button>
                <button
                    v-if="props.vault.membership.role === 'owner'"
                    type="button"
                    class="text-2xs text-muted hover:text-accent"
                    @click="destroy"
                >
                    delete vault
                </button>
            </div>
        </div>

        <form v-if="creating" class="panel mt-6 space-y-6 p-4" @submit.prevent="create">
            <TextField v-model="name" label="name" autofocus hint="Encrypted before it leaves this page." />
            <TextField v-model="description" label="description" />

            <NoticePanel v-if="createFailure" tone="accent">{{ createFailure }}</NoticePanel>

            <button type="submit" class="btn btn-primary" :disabled="!name">create lockbox</button>
        </form>

        <!--
            Progress rather than a spinner. Decrypting a large vault takes real
            time, and a number that moves is the difference between "working"
            and "broken" — the one thing a spinner cannot tell you.
        -->
        <div
            v-if="showProgress"
            class="mt-6"
            role="status"
            aria-live="polite"
            :aria-label="`Decrypting ${progress.done} of ${progress.total} items`"
        >
            <p class="text-sm text-muted">decrypting {{ progress.done }} / {{ progress.total }}…</p>
            <div class="mt-2 h-px w-full bg-line">
                <div class="h-px bg-accent" :style="{ width: `${percent}%` }" />
            </div>
        </div>

        <div v-else-if="openedLockboxes.length" class="panel mt-6 divide-y divide-line">
            <div v-for="entry in openedLockboxes" :key="entry.record.uuid" class="p-4">
                <NoticePanel v-if="entry.error" tone="accent" heading="integrity failure">
                    {{ entry.error }}
                </NoticePanel>

                <Link v-else :href="`/lockboxes/${entry.record.uuid}`" class="flex justify-between gap-4">
                    <span>
                        <span class="text-sm">{{ entry.payload?.name }}</span>
                        <span v-if="entry.payload?.description" class="mt-1 block text-2xs text-muted">
                            {{ entry.payload.description }}
                        </span>
                    </span>
                    <span class="text-2xs text-faint">
                        {{ secretsIn(entry.record.uuid).length }}
                        {{ secretsIn(entry.record.uuid).length === 1 ? 'secret' : 'secrets' }}
                    </span>
                </Link>
            </div>
        </div>

        <p v-else-if="!failure && !busy" class="mt-6 text-sm text-muted">No lockboxes in this vault yet.</p>
    </AppLayout>
</template>
