<script setup lang="ts">
/**
 * Moving a vault's payloads onto the current envelope version.
 *
 * Phase 10 said old rows would "re-wrap lazily on write", which is true and is
 * not a migration: the payloads nobody edits are the majority and the
 * long-lived ones, so on its own that means "never, for exactly the data that
 * matters most". This page is what actually moves them.
 *
 * **Nothing here changes a secret.** Each payload is opened, sealed again with a
 * fresh Item Key, and written back — same plaintext, newer envelope. It is not
 * an edit, does not archive a version, and is recorded as one `vault.resealed`
 * rather than a run of changes that never happened.
 *
 * **It goes in batches, and that is safe here in a way it would not be for a
 * re-key.** Both envelope versions open, so every row is correct on its own and
 * a half-finished pass leaves nothing to repair. Closing the tab midway is fine;
 * come back and run the rest.
 */
import { Head, Link } from '@inertiajs/vue3';
import { computed, ref, watch } from 'vue';

import NoticePanel from '@/components/NoticePanel.vue';
import AppLayout from '@/layouts/AppLayout.vue';
import { describeError } from '@/lib/errors';
import type { FileRecord } from '@/lib/files';
import { postJson } from '@/lib/http';
import type { LockboxRecord, SecretRecord, VaultRecord } from '@/lib/items';
import {
    batched,
    isLegacyEnvelope,
    resealItem,
    RESEAL_BATCH_SIZE,
    type ResealCandidate,
    type ResealItem,
} from '@/lib/reseal';
import { useSession } from '@/stores/session';
import { useVaultContents } from '@/stores/vault';

const props = defineProps<{
    vault: VaultRecord;
    lockboxes: LockboxRecord[];
    secrets: SecretRecord[];
    files: FileRecord[];
}>();

const { isUnlocked, crypto } = useSession();
const { contents, busy, failure, progress, openContents } = useVaultContents();

const running = ref(false);
const done = ref(0);
const writeFailure = ref('');
const result = ref<{ applied: number; skipped: number } | null>(null);

watch(
    [() => props.vault, () => props.lockboxes, () => props.secrets, () => props.files, isUnlocked],
    async () => {
        if (isUnlocked.value) {
            await openContents(crypto(), {
                vault: props.vault,
                lockboxes: props.lockboxes,
                secrets: props.secrets,
                files: props.files,
            });
        }
    },
    { immediate: true },
);

/**
 * Everything this browser opened, with the context its payload is bound to.
 *
 * Items that failed to decrypt are absent, not merely excluded from the work: a
 * payload this browser cannot read is one it must not rewrite, because
 * re-sealing means sealing plaintext it does not have.
 */
const candidates = computed((): Array<ResealCandidate<unknown>> => {
    const opened = contents.value;
    const all: Array<ResealCandidate<unknown>> = [];

    if (opened.vault?.payload) {
        all.push({ record: props.vault, context: 'vault.payload', payload: opened.vault.payload });
    }

    for (const entry of opened.lockboxes) {
        if (entry.payload) {
            all.push({ record: entry.record, context: 'lockbox.payload', payload: entry.payload });
        }
    }

    for (const entry of opened.secrets) {
        if (entry.payload) {
            all.push({ record: entry.record, context: 'secret.payload', payload: entry.payload });
        }
    }

    for (const entry of opened.files) {
        if (entry.payload) {
            all.push({ record: entry.record, context: 'file.payload', payload: entry.payload });
        }
    }

    return all;
});

const pending = computed(() => candidates.value.filter((c) => isLegacyEnvelope(c.record.payloadCt)));

/** Rows on the old envelope that this browser could not open, so cannot move. */
const unreadable = computed(() => {
    const readable = new Set(candidates.value.map((candidate) => candidate.record.uuid));

    return [props.vault, ...props.lockboxes, ...props.secrets, ...props.files].filter(
        (record) => isLegacyEnvelope(record.payloadCt) && !readable.has(record.uuid),
    );
});

const total = computed(() => 1 + props.lockboxes.length + props.secrets.length + props.files.length);
const current = computed(() => total.value - pending.value.length - unreadable.value.length);

async function reseal(): Promise<void> {
    running.value = true;
    writeFailure.value = '';
    result.value = null;
    done.value = 0;

    const applied = { applied: 0, skipped: 0 };
    const client = crypto();

    try {
        for (const batch of batched(pending.value, RESEAL_BATCH_SIZE)) {
            const items: ResealItem[] = [];

            for (const candidate of batch) {
                items.push(await resealItem(client, props.vault.uuid, candidate));
                done.value++;
            }

            const outcome = await postJson<{ applied: number; skipped: number }>(
                `/vaults/${props.vault.uuid}/reseal`,
                { items },
            );

            applied.applied += outcome.applied;
            applied.skipped += outcome.skipped;
        }

        result.value = applied;
    } catch (error) {
        writeFailure.value = describeError(error, 'The re-seal could not be completed.');
    } finally {
        running.value = false;
    }
}
</script>

<template>
    <AppLayout>
        <Head title="Re-seal vault" />

        <Link :href="`/vaults/${vault.uuid}`" class="text-2xs text-muted hover:text-ink">
            &larr; back to vault
        </Link>

        <h1 class="mt-4 text-base font-medium">Re-seal this vault</h1>

        <div class="mt-4 max-w-prose space-y-3 text-sm text-muted">
            <p>
                Every payload here is wrapped in a versioned envelope. Older rows are still readable and
                always will be, but they do not carry the newer envelope's protections — so this opens each
                one and seals the same contents again at the current version.
            </p>
            <p class="text-ink">
                Nothing changes. Not a single secret, note or name is altered, no history is recorded, and
                nobody's access moves. Only the wrapping around the data.
            </p>
            <p>
                It runs in batches and can be stopped at any point. Both versions open, so a row is correct
                whichever it is on — unlike a re-key, half of this is not a problem.
            </p>
        </div>

        <NoticePanel v-if="!isUnlocked" tone="accent" class="mt-6">
            Unlock the vault first — re-sealing means reading every payload in it.
        </NoticePanel>

        <p v-else-if="busy" class="mt-6 text-sm text-muted" role="status">
            decrypting {{ progress.done }} / {{ progress.total }}…
        </p>

        <NoticePanel v-if="failure" tone="accent" heading="this vault could not be opened" class="mt-6">
            {{ failure }}
        </NoticePanel>

        <section v-if="isUnlocked && !busy" class="panel mt-8 p-4">
            <h2 class="text-2xs tracking-[0.08em] text-faint uppercase">what is where</h2>

            <dl class="mt-4 space-y-2 text-2xs">
                <div class="flex justify-between gap-4">
                    <dt class="text-muted">on the current envelope</dt>
                    <dd>{{ current }} of {{ total }}</dd>
                </div>
                <div class="flex justify-between gap-4">
                    <dt class="text-muted">ready to move</dt>
                    <dd :class="pending.length ? 'text-accent' : ''">{{ pending.length }}</dd>
                </div>
                <div v-if="unreadable.length" class="flex justify-between gap-4">
                    <dt class="text-muted">on the old envelope and unreadable here</dt>
                    <dd class="text-accent">{{ unreadable.length }}</dd>
                </div>
            </dl>

            <!--
                Said plainly, because the number on the health report will not
                reach zero and somebody will otherwise assume the migration
                failed. An archive that could be rewritten is a rollback channel
                for a credential rotated *because* it leaked, so these stay put.
            -->
            <p class="mt-4 max-w-prose text-2xs text-faint">
                Archived versions are not included and never can be: a secret's history is immutable by
                design, so those rows stay on the old envelope until the retention policy removes them.
            </p>
        </section>

        <NoticePanel
            v-if="unreadable.length"
            tone="accent"
            heading="some payloads could not be opened"
            class="mt-6"
        >
            {{ unreadable.length }} older {{ unreadable.length === 1 ? 'payload' : 'payloads' }} did not
            decrypt in this browser, so they are left alone — re-sealing means sealing contents this page does
            not have. That is an integrity problem rather than a migration one, and it needs looking at on its
            own.
        </NoticePanel>

        <NoticePanel v-if="writeFailure" tone="accent" heading="stopped part way" class="mt-6">
            <p>{{ writeFailure }}</p>
            <p class="mt-3">
                Whatever had already been written stays written, and is correct. Run it again to finish the
                rest.
            </p>
        </NoticePanel>

        <NoticePanel v-if="result" heading="done" class="mt-6">
            <p>
                {{ result.applied }}
                {{ result.applied === 1 ? 'payload' : 'payloads' }} moved to the current envelope.
            </p>
            <p v-if="result.skipped" class="mt-3">
                {{ result.skipped }} were skipped because they changed while this was running — somebody
                edited them, which puts them on the current envelope anyway.
            </p>
        </NoticePanel>

        <div v-if="isUnlocked && !busy" class="mt-8">
            <p v-if="running" class="text-sm text-muted" role="status" aria-live="polite">
                re-sealing {{ done }} / {{ pending.length }}…
            </p>

            <button v-else-if="pending.length" type="button" class="btn btn-primary" @click="reseal">
                re-seal {{ pending.length }} {{ pending.length === 1 ? 'payload' : 'payloads' }}
            </button>

            <p v-else class="text-sm text-muted">
                Everything this browser can read is already on the current envelope.
            </p>
        </div>
    </AppLayout>
</template>
