<script setup lang="ts">
/**
 * Search across the open vault, without a single byte leaving the tab.
 *
 * The server cannot search for you — it has never seen a name — so this runs
 * against the plaintext already decrypted into the store. The consequence is
 * worth stating in the interface rather than only in a document: nobody learns
 * what you searched for, because the query never travels. That is a stronger
 * property than most password managers offer, and it is the compensation for
 * having to download the whole vault to get it.
 */
import { Link, router } from '@inertiajs/vue3';
import { computed, nextTick, onBeforeUnmount, onMounted, ref, useId, watch } from 'vue';

import { triggers } from '@/lib/shortcuts';
import { useSession } from '@/stores/session';
import { useVaultContents } from '@/stores/vault';

const { isUnlocked } = useSession();
const { contents, find } = useVaultContents();

const open = ref(false);
const query = ref('');
const active = ref(0);
const input = ref<HTMLInputElement | null>(null);
const listId = useId();

interface Result {
    id: string;
    name: string;
    detail: string;
    href: string;
    kind: 'lockbox' | 'secret';
}

const lockboxNames = computed(
    () =>
        new Map(
            contents.value.lockboxes.flatMap((entry) =>
                entry.payload ? [[entry.record.uuid, entry.payload.name] as const] : [],
            ),
        ),
);

const results = computed<Result[]>(() => {
    if (query.value.trim() === '') {
        return [];
    }

    const lockboxes = new Map(contents.value.lockboxes.map((entry) => [entry.record.uuid, entry]));
    const secrets = new Map(contents.value.secrets.map((entry) => [entry.record.uuid, entry]));

    return find(query.value).flatMap<Result>((hit) => {
        const lockbox = lockboxes.get(hit.id);

        if (lockbox?.payload) {
            return [
                {
                    id: hit.id,
                    name: lockbox.payload.name,
                    detail: 'lockbox',
                    href: `/lockboxes/${hit.id}`,
                    kind: 'lockbox',
                },
            ];
        }

        const secret = secrets.get(hit.id);

        if (!secret?.payload) {
            return [];
        }

        return [
            {
                id: hit.id,
                name: secret.payload.key,
                detail: [secret.payload.type, lockboxNames.value.get(secret.record.lockboxUuid)]
                    .filter((part) => part !== undefined && part !== '')
                    .join(' · '),
                // Secrets live on their lockbox's page; the fragment is what
                // scrolls to and focuses the row on arrival.
                href: `/lockboxes/${secret.record.lockboxUuid}#secret-${hit.id}`,
                kind: 'secret',
            },
        ];
    });
});

/** What a screen reader should call the highlighted row, if there is one. */
const activeId = computed(() => {
    const result = results.value[active.value];

    return result ? `${listId}-${result.id}` : undefined;
});

watch(results, () => (active.value = 0));

watch(open, async (isOpen) => {
    if (isOpen) {
        await nextTick();
        input.value?.focus();
    }
});

/** Locking empties the store, so a palette full of names must go with it. */
watch(isUnlocked, (unlocked) => {
    if (!unlocked) {
        close();
    }
});

function close(): void {
    open.value = false;
    query.value = '';
    active.value = 0;
}

function move(delta: number): void {
    if (results.value.length === 0) {
        return;
    }

    active.value = (active.value + delta + results.value.length) % results.value.length;
}

function onKeydown(event: KeyboardEvent): void {
    if (triggers(event, 'mod+k', event.target) || triggers(event, '/', event.target)) {
        event.preventDefault();
        open.value = isUnlocked.value;

        return;
    }

    if (!open.value) {
        return;
    }

    if (triggers(event, 'escape', event.target)) {
        event.preventDefault();
        close();

        return;
    }

    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
        event.preventDefault();
        move(event.key === 'ArrowDown' ? 1 : -1);
    }
}

function choose(): void {
    const result = results.value[active.value];

    if (!result) {
        return;
    }

    // Closed first: the visit re-renders the page underneath, and a palette
    // still open over the destination is disorienting.
    const href = result.href;

    close();
    router.visit(href);
}

onMounted(() => window.addEventListener('keydown', onKeydown));
onBeforeUnmount(() => window.removeEventListener('keydown', onKeydown));

/** So the header can offer a button for anyone not using the keyboard. */
defineExpose({ show: () => (open.value = isUnlocked.value) });
</script>

<template>
    <div
        v-if="open"
        class="fixed inset-0 z-50 flex items-start justify-center bg-black/40 px-6 pt-24"
        @click.self="close"
    >
        <div class="panel w-full max-w-2xl" role="dialog" aria-modal="true" aria-label="Search this vault">
            <div class="border-b border-line p-3">
                <input
                    ref="input"
                    v-model="query"
                    class="field border-0 p-0 focus:border-0"
                    type="text"
                    placeholder="search this vault…"
                    spellcheck="false"
                    autocapitalize="off"
                    autocomplete="off"
                    role="combobox"
                    aria-expanded="true"
                    :aria-controls="listId"
                    :aria-activedescendant="activeId"
                    @keydown.enter.prevent="choose"
                />
            </div>

            <ul v-if="results.length" :id="listId" role="listbox" class="max-h-80 overflow-y-auto">
                <li v-for="(result, position) in results" :key="result.id" role="presentation">
                    <Link
                        :id="`${listId}-${result.id}`"
                        :href="result.href"
                        role="option"
                        :aria-selected="position === active"
                        class="flex items-baseline justify-between gap-4 px-4 py-2.5"
                        :class="position === active ? 'bg-sunken' : ''"
                        @click="close"
                        @mouseenter="active = position"
                    >
                        <span class="text-sm">{{ result.name }}</span>
                        <span class="text-2xs text-faint">{{ result.detail }}</span>
                    </Link>
                </li>
            </ul>

            <p v-else-if="query.trim()" class="px-4 py-3 text-sm text-muted">
                Nothing in this vault matches
                <span class="text-ink">{{ query }}</span
                >.
            </p>

            <p v-else class="px-4 py-3 text-sm text-muted">
                Type to search names, notes, URLs and types. Values are never searched.
            </p>

            <p class="border-t border-line px-4 py-2 text-2xs text-faint">
                Searched in this tab, against data already decrypted here. Nothing was sent to the server —
                try it with the network switched off.
            </p>
        </div>
    </div>
</template>
