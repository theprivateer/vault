<script setup lang="ts">
/**
 * What a secret used to say.
 *
 * Every version on this page arrived as ciphertext under its own Item Key and
 * was opened in a Worker in this tab. The comparison below is here for the same
 * reason: the server holds neither key, so the only place two versions of a
 * password exist together is the browser looking at them.
 *
 * **This page is a liability as well as a feature, and it says so.** A history
 * of a value you rotated because it leaked is a copy of the leaked value kept
 * somewhere convenient, and the honest response is not to hide the fact but to
 * put the purge button next to it.
 */
import { Link, router } from '@inertiajs/vue3';
import { computed, ref, watch } from 'vue';

import NoticePanel from '@/components/NoticePanel.vue';
import AppLayout from '@/layouts/AppLayout.vue';
import { useDecryption } from '@/lib/decrypt';
import { describeError } from '@/lib/errors';
import {
    comparePayloads,
    openVersions,
    sealVersion,
    type OpenedVersion,
    type VersionRecord,
} from '@/lib/history';
import { openItem, openVaultKey, sealItem, PAYLOAD_VERSION } from '@/lib/items';
import type { LockboxRecord, SecretPayload, SecretRecord, VaultRecord } from '@/lib/items';
import { useSession } from '@/stores/session';
import { useDocumentTitle } from '@/lib/title';

const props = defineProps<{
    vault: VaultRecord;
    lockbox: LockboxRecord;
    secret: SecretRecord;
    versions: VersionRecord[];
}>();

const { isUnlocked, crypto } = useSession();
const { busy, failure, run } = useDecryption();

const current = ref<SecretPayload | null>(null);
const opened = ref<OpenedVersion[]>([]);
const compareWith = ref<string | null>(null);
const writeFailure = ref('');
const confirmingPurge = ref(false);

const canWrite = computed(() => props.vault.membership.role !== 'viewer');

/**
 * The version being compared against the live payload.
 *
 * One side of the comparison is always the present. A history view that let you
 * diff two arbitrary old versions against each other would answer a question
 * nobody asks — what people want to know is what a value used to be and what it
 * is now.
 */
const selected = computed<OpenedVersion | null>(
    () => opened.value.find((entry) => entry.record.uuid === compareWith.value) ?? null,
);

const differences = computed(() => {
    if (!selected.value?.payload || !current.value) {
        return [];
    }

    return comparePayloads(selected.value.payload, current.value).filter((field) => field.changed);
});

watch(
    [() => props.secret, () => props.versions, isUnlocked],
    () => {
        if (!isUnlocked.value) {
            return;
        }

        void load();
    },
    { immediate: true },
);

/**
 * Opens the vault key, then the live payload, then every archived one.
 *
 * The live payload is decrypted here rather than read out of the vault store,
 * because this page can be reached directly and the store may hold nothing. It
 * is one item.
 */
async function load(): Promise<void> {
    await run(async () => {
        const client = crypto();

        await openVaultKey(client, props.vault);

        current.value = await openItem<SecretPayload>(
            client,
            props.vault.uuid,
            'secret.payload',
            props.secret,
        );

        opened.value = await openVersions(client, props.vault.uuid, props.versions);
        compareWith.value = opened.value[0]?.record.uuid ?? null;
    });
}

/**
 * Puts an old payload back as a new version.
 *
 * Never destructive, and not because this function is careful — because it is
 * an ordinary edit. It posts to the same endpoint with the same
 * `expected_version` guard and archives the payload it replaces, exactly as
 * typing the old value in by hand would have. `restored_from` changes what the
 * audit log says and nothing else.
 */
async function restore(entry: OpenedVersion): Promise<void> {
    if (!entry.payload || !current.value) {
        return;
    }

    writeFailure.value = '';

    let sealed;
    let archived;

    try {
        const client = crypto();

        sealed = await sealItem(client, props.vault.uuid, 'secret.payload', props.secret.uuid, entry.payload);
        archived = await sealVersion(client, props.vault.uuid, current.value);
    } catch (error) {
        writeFailure.value = describeError(error, 'The restored version could not be encrypted.');

        return;
    }

    router.patch(
        `/secrets/${props.secret.uuid}`,
        {
            ...sealed,
            ...archived,
            payload_version: PAYLOAD_VERSION,
            linked_lockbox_uuid: props.secret.linkedLockboxUuid,
            expected_version: props.secret.version,
            restored_from: entry.record.version,
        },
        {
            onError: (errors) => {
                writeFailure.value = Object.values(errors)[0] ?? 'The version could not be restored.';
            },
        },
    );
}

function purge(): void {
    writeFailure.value = '';
    confirmingPurge.value = false;

    router.delete(`/secrets/${props.secret.uuid}/history`, {
        onError: (errors) => {
            writeFailure.value = Object.values(errors)[0] ?? 'The history could not be erased.';
        },
    });
}

function when(iso: string): string {
    return new Date(iso).toLocaleString();
}

useDocumentTitle('History');
</script>

<template>
    <AppLayout>
        <Link :href="`/lockboxes/${lockbox.uuid}`" class="text-2xs text-muted hover:text-ink">
            &larr; back to lockbox
        </Link>

        <div class="mt-4 flex items-baseline justify-between gap-4">
            <div>
                <h1 class="text-base font-medium">{{ current?.key ?? 'history' }}</h1>
                <p class="mt-1 text-2xs tracking-[0.08em] text-faint uppercase">
                    version {{ secret.version }} &middot; {{ versions.length }} kept
                </p>
            </div>

            <button
                v-if="canWrite && versions.length"
                type="button"
                class="btn"
                @click="confirmingPurge = true"
            >
                erase history
            </button>
        </div>

        <NoticePanel heading="history is useful and history is a liability" class="mt-4">
            Every entry below is a value this secret used to hold, kept encrypted and readable by anyone who
            can read the secret itself. If you rotated something <em>because it leaked</em>, the old value is
            still here until you erase it — this vault keeps {{ vault.history.maxVersions }} version{{
                vault.history.maxVersions === 1 ? '' : 's'
            }}
            for {{ vault.history.maxAgeDays }} days.
        </NoticePanel>

        <NoticePanel v-if="confirmingPurge" tone="accent" heading="erase every earlier version?" class="mt-4">
            This cannot be undone and there is no grace period — a grace period would defeat the point. The
            secret itself is untouched, and the activity log records that the history was erased, but not what
            was in it.
            <div class="mt-3 flex gap-3">
                <button type="button" class="btn btn-primary" @click="purge">
                    erase {{ versions.length }}
                </button>
                <button type="button" class="btn" @click="confirmingPurge = false">cancel</button>
            </div>
        </NoticePanel>

        <NoticePanel v-if="failure" tone="accent" heading="this history could not be opened" class="mt-4">
            {{ failure }}
        </NoticePanel>

        <NoticePanel v-if="writeFailure" tone="accent" heading="not saved" class="mt-4">
            {{ writeFailure }}
        </NoticePanel>

        <p v-if="busy" class="mt-6 text-sm text-muted" role="status">decrypting history…</p>

        <p v-else-if="!versions.length" class="mt-6 text-sm text-muted">
            This secret has never been edited, so there is nothing behind it yet.
        </p>

        <template v-else>
            <div class="panel mt-6 divide-y divide-line">
                <div
                    v-for="entry in opened"
                    :key="entry.record.uuid"
                    class="flex items-baseline justify-between gap-4 p-4"
                >
                    <div>
                        <p class="text-sm">
                            version {{ entry.record.version }}
                            <span v-if="entry.record.uuid === compareWith" class="ml-2 text-2xs text-accent"
                                >comparing</span
                            >
                        </p>
                        <p class="text-2xs text-muted">
                            {{ when(entry.record.createdAt) }}
                            <template v-if="entry.record.author">
                                &middot; {{ entry.record.author }}</template
                            >
                        </p>
                        <p v-if="entry.error" class="mt-1 text-2xs text-accent">{{ entry.error }}</p>
                    </div>

                    <div class="flex items-center gap-3 text-2xs">
                        <button
                            v-if="entry.payload"
                            type="button"
                            class="text-muted hover:text-ink"
                            :aria-label="`Compare version ${entry.record.version} with the current value`"
                            @click="compareWith = entry.record.uuid"
                        >
                            compare
                        </button>
                        <button
                            v-if="canWrite && entry.payload"
                            type="button"
                            class="text-muted hover:text-accent"
                            :aria-label="`Restore version ${entry.record.version} as a new version`"
                            @click="restore(entry)"
                        >
                            restore
                        </button>
                    </div>
                </div>
            </div>

            <section v-if="selected?.payload" class="mt-8">
                <h2 class="text-sm">
                    version {{ selected.record.version }}
                    <span aria-hidden="true">&rarr;</span>
                    <span class="sr-only">compared with</span>
                    now
                </h2>

                <p v-if="!differences.length" class="mt-2 text-sm text-muted">
                    Nothing differs between this version and the current value.
                </p>

                <div v-for="field in differences" :key="field.field" class="mt-4">
                    <p class="text-2xs tracking-[0.08em] text-faint uppercase">{{ field.field }}</p>

                    <div class="panel mt-1 divide-y divide-line text-sm">
                        <p
                            v-for="(op, at) in field.ops"
                            :key="at"
                            class="px-3 py-1 break-all whitespace-pre-wrap"
                            :class="{
                                'text-muted': op.kind === 'same',
                                'text-accent line-through': op.kind === 'removed',
                                'text-ink': op.kind === 'added',
                            }"
                        >
                            <span aria-hidden="true" class="mr-2 text-faint">{{
                                op.kind === 'removed' ? '-' : op.kind === 'added' ? '+' : ' '
                            }}</span>
                            <span class="sr-only">{{ op.kind }}:</span>{{ op.text }}
                        </p>
                    </div>
                </div>
            </section>
        </template>
    </AppLayout>
</template>
