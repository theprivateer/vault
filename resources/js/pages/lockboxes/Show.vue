<script setup lang="ts">
/**
 * One lockbox, and the secrets in it.
 *
 * This is the page the 2017 application rendered from server-decrypted
 * plaintext. Here the response carried nothing but ciphertext, and every value
 * below was opened in a Worker in this tab.
 *
 * Writes are applied optimistically: the plaintext is already in hand — this
 * page encrypted it a moment ago — so there is nothing to guess at, and the
 * only honest thing to do with a failure is put the row back exactly as it was.
 */
import { Link, router } from '@inertiajs/vue3';
import { computed, ref, watch } from 'vue';

import FileAttachments from '@/components/FileAttachments.vue';
import NoticePanel from '@/components/NoticePanel.vue';
import SecretFieldInput from '@/components/SecretFieldInput.vue';
import SecretRow from '@/components/SecretRow.vue';
import ShareSecret from '@/components/ShareSecret.vue';
import TextField from '@/components/TextField.vue';
import AppLayout from '@/layouts/AppLayout.vue';
import { describeError } from '@/lib/errors';
import type { FileRecord } from '@/lib/files';
import { sealVersion } from '@/lib/history';
import {
    PAYLOAD_VERSION,
    sealItem,
    type LockboxRecord,
    type SecretPayload,
    type SecretRecord,
    type VaultRecord,
} from '@/lib/items';
import { search, buildIndex } from '@/lib/search';
import {
    ALL_FIELD_KEYS,
    buildPayload,
    fieldsFor,
    isKnownType,
    readField,
    searchFieldsFor,
    SECRET_TYPES,
    SECRET_TYPE_ORDER,
    unmappedFields,
    type SecretFieldKey,
} from '@/lib/secretTypes';
import { uuid7 } from '@/lib/uuid';
import { useSession } from '@/stores/session';
import { useVaultContents, type OpenedSecret } from '@/stores/vault';
import { useDocumentTitle } from '@/lib/title';

const props = defineProps<{
    vault: VaultRecord;
    lockbox: LockboxRecord;
    secrets: SecretRecord[];
    lockboxes: LockboxRecord[];
    files: FileRecord[];
    shareLimits: { defaultHours: number; maxHours: number; maxViews: number };
}>();

const { isUnlocked, crypto } = useSession();
const {
    contents,
    busy,
    failure,
    progress,
    showProgress,
    openContents,
    secretsIn,
    filesIn,
    applyOptimistic,
    removeOptimistic,
} = useVaultContents();

/**
 * The form's shape: every field made a concrete string for `v-model`.
 *
 * `unknown` carries anything the payload held that this build's schema has no
 * field for — an item written by a later build, or a `card` from before cards
 * had fields. It is not rendered, and it is written straight back on save. An
 * editor that dropped what it could not display would turn "we cannot show this"
 * into "this is gone", silently, on the first edit.
 */
type SecretDraft = Record<SecretFieldKey, string> & {
    type: string;
    key: string;
    paranoid: boolean;
    unknown: Record<string, string>;
};

const editing = ref<string | null>(null);
const sharing = ref<string | null>(null);
const draft = ref<SecretDraft>(emptyDraft());
const writeFailure = ref('');
const filter = ref('');

const canWrite = computed(() => props.vault.membership.role !== 'viewer');

/** The fields the open form shows, which change as the type picker changes. */
const draftFields = computed(() => fieldsFor(draft.value.type));

const typeDescription = computed(() =>
    isKnownType(draft.value.type) ? SECRET_TYPES[draft.value.type].description : '',
);

/** Lockboxes this vault holds, by name, for the `lockbox` control. */
const lockboxOptions = computed(() =>
    props.lockboxes.map((box) => ({ uuid: box.uuid, name: names.value.get(box.uuid) ?? box.uuid })),
);

/** Names of the vault's lockboxes, so a link can be rendered by name. */
const names = computed(
    () =>
        new Map(
            contents.value.lockboxes.flatMap((entry) =>
                entry.payload ? [[entry.record.uuid, entry.payload.name] as const] : [],
            ),
        ),
);

const openedLockbox = computed(
    () => contents.value.lockboxes.find((entry) => entry.record.uuid === props.lockbox.uuid) ?? null,
);

const inLockbox = computed(() => secretsIn(props.lockbox.uuid));

const attachments = computed(() => filesIn(props.lockbox.uuid));

/**
 * The visible list, narrowed by the filter.
 *
 * A local index over this one lockbox rather than the store's vault-wide one:
 * the filter box is scoped to what is on screen, and the palette (`/`) is the
 * thing that searches the whole vault. Two boxes that look the same and search
 * different sets would be worse than either.
 */
const visible = computed<OpenedSecret[]>(() => {
    if (filter.value.trim() === '') {
        return inLockbox.value;
    }

    const index = buildIndex(
        inLockbox.value.flatMap((entry) =>
            entry.payload ? [{ id: entry.record.uuid, fields: searchFieldsFor(entry.payload) }] : [],
        ),
    );

    const ranked = new Set(search(index, filter.value).map((hit) => hit.id));

    return inLockbox.value.filter((entry) => ranked.has(entry.record.uuid));
});

const percent = computed(() =>
    progress.value.total === 0 ? 0 : Math.round((progress.value.done / progress.value.total) * 100),
);

/**
 * A blank draft with every field key present and empty.
 *
 * All of them, not just the chosen type's, purely so that switching the type
 * picker mid-edit never leaves a `v-model` bound to an absent key. It says
 * nothing about what gets stored: `buildPayload` drops the empties and the ones
 * this type does not show, which is deliberate and is explained where it
 * happens.
 */
function emptyDraft(): SecretDraft {
    const fields = Object.fromEntries(ALL_FIELD_KEYS.map((key) => [key, ''])) as Record<
        SecretFieldKey,
        string
    >;

    return { ...fields, type: 'password', key: '', paranoid: false, unknown: {} };
}

/**
 * The secret currently being shared, with its plaintext.
 *
 * A share re-encrypts the *decrypted* payload under a new key, so the panel can
 * only open for a row this tab has actually opened — which is also why sharing a
 * secret whose ciphertext failed to verify is impossible rather than merely
 * discouraged.
 */
const shared = computed(() => inLockbox.value.find((entry) => entry.record.uuid === sharing.value) ?? null);

watch(
    [() => props.vault, () => props.lockboxes, () => props.secrets, () => props.files, isUnlocked],
    async () => {
        if (!isUnlocked.value) {
            return;
        }

        await openContents(crypto(), {
            vault: props.vault,
            lockboxes: props.lockboxes,
            secrets: props.secrets,
            files: props.files,
        });
    },
    { immediate: true },
);

function startCreate(): void {
    editing.value = 'new';
    sharing.value = null;
    writeFailure.value = '';
    draft.value = emptyDraft();
}

function startEdit(entry: OpenedSecret): void {
    if (!entry.payload) {
        return;
    }

    editing.value = entry.record.uuid;
    sharing.value = null;
    writeFailure.value = '';

    const payload = entry.payload;
    const blank = emptyDraft();
    const known = Object.fromEntries(ALL_FIELD_KEYS.map((key) => [key, readField(payload, key)])) as Record<
        SecretFieldKey,
        string
    >;

    draft.value = {
        ...blank,
        ...known,
        type: payload.type,
        key: payload.key,
        paranoid: payload.paranoid ?? false,
        // Carried through the edit untouched. See the note on SecretDraft.
        unknown: Object.fromEntries(unmappedFields(payload).map((entry) => [entry.field.key, entry.value])),
        linkedLockboxUuid: entry.record.linkedLockboxUuid ?? '',
    };
}

/**
 * Encrypts under a brand new Item Key and posts the result.
 *
 * On edit as well as create: re-using the key would encrypt two plaintexts
 * under one key and would leave a rotated password readable to anyone holding
 * the old one.
 *
 * `expected_version` carries what this page believed when the form was opened.
 * The server refuses the write if someone else has saved since, because there
 * is no merge available to it — both versions are ciphertext under different
 * keys, and merging would mean reading them.
 */
async function save(): Promise<void> {
    writeFailure.value = '';

    const { linkedLockboxUuid, unknown, paranoid, type, key, ...fields } = draft.value;

    // Assembled in lib/secretTypes.ts, where its three rules can be asserted.
    const payload = buildPayload({ type, key, fields, paranoid, unknown }) as SecretPayload;

    const isNew = editing.value === 'new';
    const uuid = isNew ? uuid7() : (editing.value ?? '');
    const existing = inLockbox.value.find((entry) => entry.record.uuid === uuid);

    /*
     | An edit has to hand over the payload it is replacing, re-sealed as its
     | own archived version. The server requires it, because "writes append
     | rather than overwrite" is only true if a write that does not append is
     | refused.
     |
     | It is sealed here rather than copied server-side on purpose: a copy would
     | carry the live payload's associated data, so any archived version could
     | be written back over the live row and would verify — a silent rollback to
     | a password that was rotated because it leaked. See lib/history.ts.
     */
    const superseded = existing?.payload ?? null;

    if (!isNew && superseded === null) {
        writeFailure.value =
            'This secret could not be read, so there is nothing to keep as its previous version. ' +
            'Delete it and add it again — that keeps the unreadable copy rather than writing over it.';

        return;
    }

    let sealed;
    let archived;

    try {
        sealed = await sealItem(crypto(), props.vault.uuid, 'secret.payload', uuid, payload);
        archived = superseded ? await sealVersion(crypto(), props.vault.uuid, superseded) : null;
    } catch (error) {
        writeFailure.value = describeError(error, 'The secret could not be encrypted.');

        return;
    }

    const record: SecretRecord = {
        uuid,
        lockboxUuid: props.lockbox.uuid,
        payloadCt: sealed.payload_ct,
        wrappedItemKey: sealed.wrapped_item_key,
        payloadVersion: PAYLOAD_VERSION,
        version: (existing?.record.version ?? 0) + 1,
        sortOrder: existing?.record.sortOrder ?? props.secrets.length,
        linkedLockboxUuid: linkedLockboxUuid === '' ? null : linkedLockboxUuid,
        historyCount: (existing?.record.historyCount ?? 0) + (archived ? 1 : 0),
        updatedAt: null,
    };

    const rollback = applyOptimistic({ record, payload, error: null });

    editing.value = null;

    const body = {
        ...sealed,
        linked_lockbox_uuid: record.linkedLockboxUuid,
    };

    const handlers = {
        onError: (errors: Record<string, string>) => {
            rollback();
            editing.value = isNew ? 'new' : uuid;
            writeFailure.value = Object.values(errors)[0] ?? 'The secret could not be saved.';
        },
    };

    if (isNew) {
        router.post(
            `/lockboxes/${props.lockbox.uuid}/secrets`,
            { uuid, ...body, sort_order: record.sortOrder },
            handlers,
        );
    } else {
        router.patch(
            `/secrets/${uuid}`,
            { ...body, ...archived, expected_version: existing?.record.version ?? 1 },
            handlers,
        );
    }
}

/**
 * Reloads only the file list after an upload.
 *
 * Not optimistic, unlike a secret. A secret's plaintext is in hand before the
 * request goes out; a file's row does not exist until the server has made one,
 * and the manifest the list renders from is ciphertext this page would have to
 * invent. Asking for the real row is both simpler and honest about what is
 * actually stored.
 */
function reloadFiles(): void {
    router.reload({ only: ['files'] });
}

function removeFile(uuid: string): void {
    writeFailure.value = '';

    router.delete(`/files/${uuid}`, {
        onError: (errors) => {
            writeFailure.value = Object.values(errors)[0] ?? 'The file could not be deleted.';
        },
    });
}

function startShare(entry: OpenedSecret): void {
    editing.value = null;
    writeFailure.value = '';
    sharing.value = entry.payload ? entry.record.uuid : null;
}

function remove(uuid: string): void {
    const rollback = removeOptimistic(uuid);

    router.delete(`/secrets/${uuid}`, {
        onError: (errors) => {
            rollback();
            writeFailure.value = Object.values(errors)[0] ?? 'The secret could not be deleted.';
        },
    });
}

useDocumentTitle(() => openedLockbox.value?.payload?.name ?? 'Lockbox');
</script>

<template>
    <AppLayout>
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

        <NoticePanel v-if="openedLockbox?.error" tone="accent" heading="integrity failure" class="mt-4">
            {{ openedLockbox.error }}
        </NoticePanel>
        <NoticePanel v-if="failure" tone="accent" heading="this vault could not be opened" class="mt-4">
            {{ failure }}
        </NoticePanel>

        <form v-if="editing" class="panel mt-6 space-y-6 p-4" @submit.prevent="save">
            <div>
                <label class="label" for="secret-type">type</label>
                <select id="secret-type" v-model="draft.type" class="field">
                    <option v-for="type in SECRET_TYPE_ORDER" :key="type" :value="type">
                        {{ SECRET_TYPES[type].label }}
                    </option>
                </select>
                <p class="mt-1.5 text-2xs text-muted">
                    {{ typeDescription }}
                </p>
            </div>

            <TextField v-model="draft.key" label="name" autofocus />

            <!--
                The type's own fields, from lib/secretTypes.ts. Keyed by type as
                well as by field so that switching the picker rebuilds the
                inputs rather than reusing one across two different meanings —
                a card's security code and a note's body must not share a
                component instance.
            -->
            <SecretFieldInput
                v-for="field in draftFields"
                :key="`${draft.type}-${field.key}`"
                v-model="draft[field.key]"
                :field="field"
                :lockboxes="lockboxOptions"
            />

            <label class="flex items-center gap-2 text-2xs text-muted">
                <input v-model="draft.paranoid" type="checkbox" />
                confirm before revealing
            </label>

            <NoticePanel v-if="writeFailure" tone="accent" heading="not saved">
                {{ writeFailure }}
            </NoticePanel>

            <div class="flex gap-3">
                <button type="submit" class="btn btn-primary" :disabled="!draft.key">save</button>
                <button type="button" class="btn" @click="editing = null">cancel</button>
            </div>
        </form>

        <NoticePanel v-else-if="writeFailure" tone="accent" heading="not saved" class="mt-6">
            {{ writeFailure }}
        </NoticePanel>

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

        <template v-else-if="inLockbox.length">
            <div class="mt-6">
                <TextField
                    v-model="filter"
                    label="filter this lockbox"
                    placeholder="type to narrow…"
                    hint="Runs here, against data already decrypted in this tab. Press / to search the whole vault."
                />
            </div>

            <div v-if="visible.length" class="panel mt-4 divide-y divide-line">
                <SecretRow
                    v-for="entry in visible"
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
                    @share="startShare(entry)"
                    @remove="remove(entry.record.uuid)"
                />
            </div>

            <p v-else class="mt-4 text-sm text-muted" role="status">
                Nothing in this lockbox matches <span class="text-ink">{{ filter }}</span
                >.
            </p>
        </template>

        <p v-else-if="!failure && !busy" class="mt-6 text-sm text-muted">No secrets in this lockbox yet.</p>

        <ShareSecret
            v-if="shared?.payload"
            class="mt-6"
            :secret-uuid="shared.record.uuid"
            :payload="shared.payload"
            :default-hours="shareLimits.defaultHours"
            :max-hours="shareLimits.maxHours"
            :max-views="shareLimits.maxViews"
            @close="sharing = null"
        />

        <FileAttachments
            v-if="!failure"
            class="mt-10"
            :files="attachments"
            :vault-uuid="vault.uuid"
            :lockbox-uuid="lockbox.uuid"
            :can-write="canWrite"
            :crypto="crypto"
            @changed="reloadFiles"
            @remove="removeFile"
        />
    </AppLayout>
</template>
