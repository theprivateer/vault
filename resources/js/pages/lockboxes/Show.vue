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
import PasswordGenerator from '@/components/PasswordGenerator.vue';
import SecretRow from '@/components/SecretRow.vue';
import ShareSecret from '@/components/ShareSecret.vue';
import StrengthMeter from '@/components/StrengthMeter.vue';
import TextField from '@/components/TextField.vue';
import AppLayout from '@/layouts/AppLayout.vue';
import { describeError } from '@/lib/errors';
import type { FileRecord } from '@/lib/files';
import { sealVersion } from '@/lib/history';
import { parseOtpauth } from '@/crypto/totp';
import {
    PAYLOAD_VERSION,
    sealItem,
    type LockboxRecord,
    type SecretPayload,
    type SecretRecord,
    type SecretType,
    type VaultRecord,
} from '@/lib/items';
import { search, buildIndex } from '@/lib/search';
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

/** The form's shape: every optional payload field made concrete for v-model. */
type SecretDraft = Omit<SecretPayload, 'url' | 'paranoid' | 'totp'> & {
    url: string;
    paranoid: boolean;
    totp: string;
    linkedLockboxUuid: string;
};

const editing = ref<string | null>(null);
const sharing = ref<string | null>(null);
const showGenerator = ref(false);
const totpFailure = ref('');
const draft = ref<SecretDraft>(emptyDraft());
const writeFailure = ref('');
const filter = ref('');

const canWrite = computed(() => props.vault.membership.role !== 'viewer');

const SECRET_TYPES: SecretType[] = ['password', 'note', 'key', 'card', 'lockbox'];

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
            entry.payload
                ? [
                      {
                          id: entry.record.uuid,
                          fields: {
                              name: entry.payload.key,
                              notes: entry.payload.notes,
                              url: entry.payload.url ?? '',
                              type: entry.payload.type,
                          },
                      },
                  ]
                : [],
        ),
    );

    const ranked = new Set(search(index, filter.value).map((hit) => hit.id));

    return inLockbox.value.filter((entry) => ranked.has(entry.record.uuid));
});

const percent = computed(() =>
    progress.value.total === 0 ? 0 : Math.round((progress.value.done / progress.value.total) * 100),
);

function emptyDraft(): SecretDraft {
    return {
        type: 'password',
        key: '',
        value: '',
        notes: '',
        url: '',
        paranoid: false,
        totp: '',
        linkedLockboxUuid: '',
    };
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

/**
 * Accepts either a bare base32 seed or a whole `otpauth://` URI.
 *
 * Pasting the URI is what people actually have — it is what a QR code encodes,
 * and most setup pages offer it as "can't scan?" text. Parsing it here means the
 * issuer and account travel no further than this function; only the seed is
 * kept, because the rest is somebody else's label for an account we already have
 * a name for.
 *
 * **There is no camera scanner**, and that is a decision rather than an
 * omission. `Permissions-Policy` denies `camera=()` outright, lifting it would
 * weaken a header that currently denies everything, and a QR decoder is another
 * dependency for a path that ends at the same string this field accepts.
 */
function readTotp(value: string): string {
    totpFailure.value = '';

    const trimmed = value.trim();

    if (trimmed === '' || !trimmed.toLowerCase().startsWith('otpauth:')) {
        return trimmed;
    }

    try {
        return parseOtpauth(trimmed).secret;
    } catch (error) {
        totpFailure.value = describeError(error, 'That one-time-password URI could not be read.');

        return '';
    }
}

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
    showGenerator.value = false;
    totpFailure.value = '';
    writeFailure.value = '';
    draft.value = emptyDraft();
}

function startEdit(entry: OpenedSecret): void {
    if (!entry.payload) {
        return;
    }

    editing.value = entry.record.uuid;
    sharing.value = null;
    showGenerator.value = false;
    totpFailure.value = '';
    writeFailure.value = '';
    draft.value = {
        ...entry.payload,
        url: entry.payload.url ?? '',
        paranoid: entry.payload.paranoid ?? false,
        totp: entry.payload.totp ?? '',
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

    const { linkedLockboxUuid, totp, ...rest } = draft.value;

    /*
     | An empty seed is dropped rather than stored as "". A payload carrying
     | `totp: ''` would make every row look like it has a one-time code and give
     | the interface a blank ring to render, and the padding means the absent
     | field costs nothing to omit.
     */
    const payload: SecretPayload = totp === '' ? rest : { ...rest, totp };
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
                    <option v-for="type in SECRET_TYPES" :key="type" :value="type">{{ type }}</option>
                </select>
            </div>

            <TextField v-model="draft.key" label="name" autofocus />

            <div>
                <TextField v-model="draft.value" label="value" />
                <StrengthMeter :password="draft.value" class="mt-2" />

                <button
                    type="button"
                    class="mt-2 text-2xs text-muted hover:text-ink"
                    :aria-expanded="showGenerator"
                    @click="showGenerator = !showGenerator"
                >
                    {{ showGenerator ? 'hide generator' : 'generate one' }}
                </button>

                <PasswordGenerator
                    v-if="showGenerator"
                    class="mt-3"
                    @use="
                        (value) => {
                            draft.value = value;
                            showGenerator = false;
                        }
                    "
                />
            </div>

            <TextField v-model="draft.notes" label="notes" />
            <TextField v-model="draft.url" label="url" />

            <div>
                <TextField
                    :model-value="draft.totp"
                    label="one-time password seed"
                    placeholder="base32 seed, or paste a whole otpauth:// link"
                    hint="Stays inside the encrypted payload, like everything else. Paste the setup link a site gives you when you cannot scan its QR code."
                    @update:model-value="(value: string) => (draft.totp = readTotp(value))"
                />
                <p v-if="totpFailure" class="mt-1 text-2xs text-accent">{{ totpFailure }}</p>
            </div>

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
