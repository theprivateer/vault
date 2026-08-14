<script setup lang="ts">
/**
 * The vault list.
 *
 * Every name on this page was decrypted here, in this browser, moments before
 * it was rendered. The server sent a list of UUIDs, timestamps and opaque
 * blobs, and has no idea what any of them are called.
 */
import { Head, Link, router } from '@inertiajs/vue3';
import { ref, watch } from 'vue';

import NoticePanel from '@/components/NoticePanel.vue';
import TextField from '@/components/TextField.vue';
import AppLayout from '@/layouts/AppLayout.vue';
import { openVault, useDecryption, type Opened } from '@/lib/decrypt';
import { sealNewVault, type VaultPayload, type VaultRecord } from '@/lib/items';
import { useShared } from '@/lib/page';
import { uuid7 } from '@/lib/uuid';
import { useSession } from '@/stores/session';

const props = defineProps<{ vaults: VaultRecord[] }>();

const page = useShared();
const { isUnlocked, crypto } = useSession();
const { busy, failure, run } = useDecryption();

const opened = ref<Array<Opened<VaultRecord, VaultPayload>>>([]);

const creating = ref(false);
const name = ref('');
const description = ref('');
const createFailure = ref('');

/**
 * Re-runs whenever the list changes or the vault is unlocked, because both are
 * reasons the plaintext on screen is no longer correct.
 */
watch(
    [() => props.vaults, isUnlocked],
    async () => {
        opened.value = [];

        if (!isUnlocked.value) {
            return;
        }

        await run(async () => {
            const client = crypto();

            opened.value = await Promise.all(
                props.vaults.map((vault) => openVault<VaultPayload>(client, vault)),
            );
        });
    },
    { immediate: true },
);

async function create(): Promise<void> {
    createFailure.value = '';

    const identity = page.props.auth.identity;

    if (!identity) {
        createFailure.value = 'Your account has no identity keys, so a vault key cannot be sealed to you.';

        return;
    }

    try {
        const sealed = await sealNewVault(crypto(), uuid7(), uuid7(), identity.x25519PublicKey, {
            name: name.value,
            description: description.value,
        });

        // Only ciphertext leaves. The name above never touches the network.
        router.post(
            '/vaults',
            { ...sealed },
            {
                onSuccess: () => {
                    name.value = '';
                    description.value = '';
                    creating.value = false;
                },
            },
        );
    } catch (error) {
        createFailure.value = error instanceof Error ? error.message : 'The vault could not be encrypted.';
    }
}
</script>

<template>
    <AppLayout>
        <Head title="Vaults" />

        <div class="flex items-baseline justify-between gap-4">
            <div>
                <h1 class="text-base font-medium">Your vaults</h1>
                <p class="mt-1 text-sm text-muted">
                    {{ opened.length }} {{ opened.length === 1 ? 'vault' : 'vaults' }}, decrypted in this
                    browser.
                </p>
            </div>

            <button type="button" class="btn" @click="creating = !creating">
                {{ creating ? 'cancel' : 'new vault' }}
            </button>
        </div>

        <form v-if="creating" class="panel mt-6 space-y-6 p-4" @submit.prevent="create">
            <TextField v-model="name" label="name" autofocus hint="Encrypted before it leaves this page." />
            <TextField v-model="description" label="description" />

            <NoticePanel v-if="createFailure" tone="accent">{{ createFailure }}</NoticePanel>

            <button type="submit" class="btn btn-primary" :disabled="!name">create vault</button>
        </form>

        <NoticePanel v-if="failure" tone="accent" class="mt-6">{{ failure }}</NoticePanel>

        <p v-if="busy" class="mt-6 text-sm text-muted">decrypting…</p>

        <div v-else-if="opened.length" class="panel mt-6 divide-y divide-line">
            <div v-for="entry in opened" :key="entry.record.uuid" class="p-4">
                <NoticePanel v-if="entry.error" tone="accent">{{ entry.error }}</NoticePanel>

                <Link v-else :href="`/vaults/${entry.record.uuid}`" class="block">
                    <span class="text-sm">{{ entry.payload?.name }}</span>
                    <span v-if="entry.payload?.description" class="ml-3 text-2xs text-muted">
                        {{ entry.payload.description }}
                    </span>
                    <span class="mt-1 block text-2xs text-faint">{{ entry.record.membership.role }}</span>
                </Link>
            </div>
        </div>

        <p v-else-if="!failure" class="mt-6 text-sm text-muted">
            No vaults yet. Create one — its name is encrypted before it is sent.
        </p>

        <!--
            D10: the threat model belongs in the product, not only in the repo.
            Phase 11 gives this a page of its own; until then it lives where
            someone will actually read it. See docs/02-threat-model.md (A3).
        -->
        <NoticePanel heading="what the server can see" class="mt-10">
            Timestamps, sizes and the shape of your data. Not names, not values, not filenames. A compromised
            server can still serve modified JavaScript to this page — that is the limit of browser-delivered
            encryption, and no amount of cryptography here removes it.
        </NoticePanel>
    </AppLayout>
</template>
