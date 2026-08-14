<script setup lang="ts">
/**
 * One lockbox, and the secrets in it.
 *
 * This is the page the 2017 application rendered from server-decrypted
 * plaintext. Here the response carried nothing but ciphertext, and every value
 * below was opened in a Worker in this tab.
 */
import { Head, Link, router } from '@inertiajs/vue3';
import { computed, ref, watch } from 'vue';

import NoticePanel from '@/components/NoticePanel.vue';
import SecretRow from '@/components/SecretRow.vue';
import TextField from '@/components/TextField.vue';
import AppLayout from '@/layouts/AppLayout.vue';
import { openAll, useDecryption, type Opened } from '@/lib/decrypt';
import {
    openVaultKey,
    sealItem,
    type LockboxPayload,
    type LockboxRecord,
    type SecretPayload,
    type SecretRecord,
    type SecretType,
    type VaultRecord,
} from '@/lib/items';
import { uuid7 } from '@/lib/uuid';
import { useSession } from '@/stores/session';

const props = defineProps<{
    vault: VaultRecord;
    lockbox: LockboxRecord;
    secrets: SecretRecord[];
    lockboxes: LockboxRecord[];
}>();

const { isUnlocked, crypto } = useSession();
const { busy, failure, run } = useDecryption();

const openedLockbox = ref<Opened<LockboxRecord, LockboxPayload> | null>(null);
const opened = ref<Array<Opened<SecretRecord, SecretPayload>>>([]);
/** Names of the vault's other lockboxes, so a link can be rendered by name. */
const names = ref<Map<string, string>>(new Map());

/** The form's shape: every optional payload field made concrete for v-model. */
type SecretDraft = Omit<SecretPayload, 'url' | 'paranoid'> & {
    url: string;
    paranoid: boolean;
    linkedLockboxUuid: string;
};

const editing = ref<string | null>(null);
const draft = ref<SecretDraft>(emptyDraft());
const writeFailure = ref('');

const canWrite = computed(() => props.vault.membership.role !== 'viewer');

const SECRET_TYPES: SecretType[] = ['password', 'note', 'key', 'card', 'lockbox'];

function emptyDraft(): SecretDraft {
    return {
        type: 'password',
        key: '',
        value: '',
        notes: '',
        url: '',
        paranoid: false,
        linkedLockboxUuid: '',
    };
}

watch(
    [() => props.secrets, isUnlocked],
    async () => {
        openedLockbox.value = null;
        opened.value = [];
        names.value = new Map();

        if (!isUnlocked.value) {
            return;
        }

        await run(async () => {
            const client = crypto();

            await openVaultKey(client, props.vault);

            const boxes = await openAll<LockboxRecord, LockboxPayload>(
                client,
                props.vault.uuid,
                'lockbox.payload',
                props.lockboxes,
                () => 'This lockbox',
            );

            for (const entry of boxes) {
                if (entry.payload) {
                    names.value.set(entry.record.uuid, entry.payload.name);
                }
            }

            openedLockbox.value = boxes.find((entry) => entry.record.uuid === props.lockbox.uuid) ?? null;

            opened.value = await openAll<SecretRecord, SecretPayload>(
                client,
                props.vault.uuid,
                'secret.payload',
                props.secrets,
                () => 'This secret',
            );
        });
    },
    { immediate: true },
);

function startCreate(): void {
    editing.value = 'new';
    draft.value = emptyDraft();
}

function startEdit(entry: Opened<SecretRecord, SecretPayload>): void {
    if (!entry.payload) {
        return;
    }

    editing.value = entry.record.uuid;
    draft.value = {
        ...entry.payload,
        url: entry.payload.url ?? '',
        paranoid: entry.payload.paranoid ?? false,
        linkedLockboxUuid: entry.record.linkedLockboxUuid ?? '',
    };
}

/**
 * Encrypts under a brand new Item Key and posts the result.
 *
 * On edit as well as create: re-using the key would encrypt two plaintexts
 * under one key and would leave a rotated password readable to anyone holding
 * the old one.
 */
async function save(): Promise<void> {
    writeFailure.value = '';

    const { linkedLockboxUuid, ...payload } = draft.value;
    const isNew = editing.value === 'new';
    const uuid = isNew ? uuid7() : (editing.value ?? '');

    try {
        const sealed = await sealItem(crypto(), props.vault.uuid, 'secret.payload', uuid, payload);

        const body = {
            ...sealed,
            linked_lockbox_uuid: linkedLockboxUuid === '' ? null : linkedLockboxUuid,
        };

        const done = { onSuccess: () => (editing.value = null) };

        if (isNew) {
            router.post(
                `/lockboxes/${props.lockbox.uuid}/secrets`,
                { uuid, ...body, sort_order: props.secrets.length },
                done,
            );
        } else {
            router.patch(`/secrets/${uuid}`, body, done);
        }
    } catch (error) {
        writeFailure.value = error instanceof Error ? error.message : 'The secret could not be encrypted.';
    }
}

function remove(uuid: string): void {
    router.delete(`/secrets/${uuid}`);
}
</script>

<template>
    <AppLayout>
        <Head :title="openedLockbox?.payload?.name ?? 'Lockbox'" />

        <Link :href="`/vaults/${vault.uuid}`" class="text-2xs text-muted hover:text-ink">
            &larr; back to vault
        </Link>

        <div class="mt-4 flex items-baseline justify-between gap-4">
            <div>
                <h1 class="text-base font-medium">{{ openedLockbox?.payload?.name ?? '—' }}</h1>
                <p v-if="openedLockbox?.payload?.description" class="mt-1 text-sm text-muted">
                    {{ openedLockbox.payload.description }}
                </p>
            </div>

            <button v-if="canWrite" type="button" class="btn" @click="startCreate">new secret</button>
        </div>

        <NoticePanel v-if="openedLockbox?.error" tone="accent" class="mt-4">{{
            openedLockbox.error
        }}</NoticePanel>
        <NoticePanel v-if="failure" tone="accent" class="mt-4">{{ failure }}</NoticePanel>

        <form v-if="editing" class="panel mt-6 space-y-6 p-4" @submit.prevent="save">
            <div>
                <label class="label" for="secret-type">type</label>
                <select id="secret-type" v-model="draft.type" class="field">
                    <option v-for="type in SECRET_TYPES" :key="type" :value="type">{{ type }}</option>
                </select>
            </div>

            <TextField v-model="draft.key" label="name" autofocus />
            <TextField v-model="draft.value" label="value" />
            <TextField v-model="draft.notes" label="notes" />
            <TextField v-model="draft.url" label="url" />

            <div>
                <label class="label" for="secret-link">linked lockbox</label>
                <select id="secret-link" v-model="draft.linkedLockboxUuid" class="field">
                    <option value="">none</option>
                    <option v-for="box in lockboxes" :key="box.uuid" :value="box.uuid">
                        {{ names.get(box.uuid) ?? box.uuid }}
                    </option>
                </select>
            </div>

            <label class="flex items-center gap-2 text-2xs text-muted">
                <input v-model="draft.paranoid" type="checkbox" />
                confirm before revealing
            </label>

            <NoticePanel v-if="writeFailure" tone="accent">{{ writeFailure }}</NoticePanel>

            <div class="flex gap-3">
                <button type="submit" class="btn btn-primary" :disabled="!draft.key">save</button>
                <button type="button" class="btn" @click="editing = null">cancel</button>
            </div>
        </form>

        <p v-if="busy" class="mt-6 text-sm text-muted">decrypting…</p>

        <div v-else-if="opened.length" class="panel mt-6 divide-y divide-line">
            <SecretRow
                v-for="entry in opened"
                :key="entry.record.uuid"
                :record="entry.record"
                :payload="entry.payload"
                :error="entry.error"
                :linked-lockbox-name="
                    entry.record.linkedLockboxUuid
                        ? (names.get(entry.record.linkedLockboxUuid) ?? null)
                        : null
                "
                :can-write="canWrite"
                @edit="startEdit(entry)"
                @remove="remove(entry.record.uuid)"
            />
        </div>

        <p v-else-if="!failure" class="mt-6 text-sm text-muted">No secrets in this lockbox yet.</p>
    </AppLayout>
</template>
