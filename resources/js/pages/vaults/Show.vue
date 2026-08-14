<script setup lang="ts">
/**
 * One vault, and the lockboxes inside it.
 */
import { Head, Link, router } from '@inertiajs/vue3';
import { ref, watch } from 'vue';

import NoticePanel from '@/components/NoticePanel.vue';
import TextField from '@/components/TextField.vue';
import AppLayout from '@/layouts/AppLayout.vue';
import { openAll, openVault, useDecryption, type Opened } from '@/lib/decrypt';
import {
    sealItem,
    type LockboxPayload,
    type LockboxRecord,
    type VaultPayload,
    type VaultRecord,
} from '@/lib/items';
import { uuid7 } from '@/lib/uuid';
import { useSession } from '@/stores/session';

const props = defineProps<{ vault: VaultRecord; lockboxes: LockboxRecord[] }>();

const { isUnlocked, crypto } = useSession();
const { busy, failure, run } = useDecryption();

const openedVault = ref<Opened<VaultRecord, VaultPayload> | null>(null);
const opened = ref<Array<Opened<LockboxRecord, LockboxPayload>>>([]);

const creating = ref(false);
const name = ref('');
const description = ref('');
const createFailure = ref('');

const canWrite = () => props.vault.membership.role !== 'viewer';

watch(
    [() => props.lockboxes, isUnlocked],
    async () => {
        openedVault.value = null;
        opened.value = [];

        if (!isUnlocked.value) {
            return;
        }

        await run(async () => {
            const client = crypto();

            // The vault key has to be in the Worker before anything under it
            // can be unwrapped, so this is sequential by necessity.
            openedVault.value = await openVault<VaultPayload>(client, props.vault);

            opened.value = await openAll<LockboxRecord, LockboxPayload>(
                client,
                props.vault.uuid,
                'lockbox.payload',
                props.lockboxes,
                () => 'This lockbox',
            );
        });
    },
    { immediate: true },
);

async function create(): Promise<void> {
    createFailure.value = '';

    try {
        const uuid = uuid7();

        const sealed = await sealItem(crypto(), props.vault.uuid, 'lockbox.payload', uuid, {
            name: name.value,
            description: description.value,
        });

        router.post(
            `/vaults/${props.vault.uuid}/lockboxes`,
            { uuid, ...sealed, sort_order: props.lockboxes.length },
            {
                onSuccess: () => {
                    name.value = '';
                    description.value = '';
                    creating.value = false;
                },
            },
        );
    } catch (error) {
        createFailure.value = error instanceof Error ? error.message : 'The lockbox could not be encrypted.';
    }
}

function destroy(): void {
    router.delete(`/vaults/${props.vault.uuid}`);
}
</script>

<template>
    <AppLayout>
        <Head :title="openedVault?.payload?.name ?? 'Vault'" />

        <Link href="/vaults" class="text-2xs text-muted hover:text-ink">&larr; all vaults</Link>

        <NoticePanel v-if="openedVault?.error" tone="accent" class="mt-4">{{
            openedVault.error
        }}</NoticePanel>

        <div v-else class="mt-4 flex items-baseline justify-between gap-4">
            <div>
                <h1 class="text-base font-medium">{{ openedVault?.payload?.name ?? '—' }}</h1>
                <p v-if="openedVault?.payload?.description" class="mt-1 text-sm text-muted">
                    {{ openedVault.payload.description }}
                </p>
            </div>

            <div class="flex items-center gap-4">
                <button v-if="canWrite()" type="button" class="btn" @click="creating = !creating">
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
            <TextField v-model="name" label="name" autofocus />
            <TextField v-model="description" label="description" />

            <NoticePanel v-if="createFailure" tone="accent">{{ createFailure }}</NoticePanel>

            <button type="submit" class="btn btn-primary" :disabled="!name">create lockbox</button>
        </form>

        <NoticePanel v-if="failure" tone="accent" class="mt-6">{{ failure }}</NoticePanel>

        <p v-if="busy" class="mt-6 text-sm text-muted">decrypting…</p>

        <div v-else-if="opened.length" class="panel mt-6 divide-y divide-line">
            <div v-for="entry in opened" :key="entry.record.uuid" class="p-4">
                <NoticePanel v-if="entry.error" tone="accent">{{ entry.error }}</NoticePanel>

                <Link v-else :href="`/lockboxes/${entry.record.uuid}`" class="flex justify-between gap-4">
                    <span>
                        <span class="text-sm">{{ entry.payload?.name }}</span>
                        <span v-if="entry.payload?.description" class="mt-1 block text-2xs text-muted">
                            {{ entry.payload.description }}
                        </span>
                    </span>
                    <span class="text-2xs text-faint">
                        {{ entry.record.secretCount }}
                        {{ entry.record.secretCount === 1 ? 'secret' : 'secrets' }}
                    </span>
                </Link>
            </div>
        </div>

        <p v-else-if="!failure" class="mt-6 text-sm text-muted">No lockboxes in this vault yet.</p>
    </AppLayout>
</template>
