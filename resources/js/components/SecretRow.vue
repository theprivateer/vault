<script setup lang="ts">
/**
 * One secret, rendered from its type's schema.
 *
 * The value is already decrypted and in memory by the time this renders —
 * masking is an interface courtesy against shoulder-surfing and screen sharing,
 * not a security boundary. Saying so plainly matters more than pretending
 * otherwise: anything that reaches this component has already been decrypted.
 *
 * Reveal is per field rather than per item, because a structured type has fields
 * of different kinds: a card's number and security code deserve a deliberate
 * click and the name printed beside them does not. `paranoid` still gates the
 * first reveal of any of them.
 */
import { Link } from '@inertiajs/vue3';
import { computed, nextTick, ref } from 'vue';

import NoticePanel from '@/components/NoticePanel.vue';
import SecretFieldValue from '@/components/SecretFieldValue.vue';
import { reportReveal } from '@/lib/audit';
import type { SecretPayload, SecretRecord } from '@/lib/items';
import { fieldsFor, labelFor, readField, unmappedFields, type SecretField } from '@/lib/secretTypes';
import { useSession } from '@/stores/session';

const props = defineProps<{
    record: SecretRecord;
    payload: SecretPayload | null;
    error: string | null;
    linkedLockboxName: string | null;
    canWrite: boolean;
}>();

const emit = defineEmits<{ edit: []; remove: []; share: [] }>();

const { crypto } = useSession();

const revealed = ref(new Set<string>());
const confirming = ref<string | null>(null);
const confirmButton = ref<HTMLButtonElement | null>(null);

const label = computed(() => props.payload?.key ?? 'this secret');

const typeLabel = computed(() => (props.payload ? labelFor(props.payload.type) : ''));

/**
 * The fields this item actually has something in.
 *
 * Empty fields are dropped rather than rendered as blank rows: an address with
 * no second line should not show one, and a password item should not advertise
 * that it has no one-time code.
 */
const populated = computed<{ field: SecretField; value: string }[]>(() => {
    const payload = props.payload;

    if (!payload) {
        return [];
    }

    return fieldsFor(payload.type).flatMap((field) => {
        // `linkedLockboxUuid` is a column rather than a payload key, and it
        // renders by name at the foot of the row instead of as a raw UUID.
        if (field.key === 'linkedLockboxUuid') {
            return [];
        }

        const value = readField(payload, field.key);

        return value === '' ? [] : [{ field, value }];
    });
});

/**
 * Anything in the payload this build's schema does not place.
 *
 * A payload written by a later build — or by an earlier one, whose `card` items
 * kept everything in `value` before cards had fields — must not have content
 * silently disappear from the page. It is shown, labelled by its raw key and
 * masked, because a field this build cannot identify is one it cannot judge safe
 * to display in the clear.
 */
const unmapped = computed(() => (props.payload ? unmappedFields(props.payload) : []));

/**
 * `paranoid` items ask before revealing.
 *
 * A confirmation step, not a re-authentication: asking for the password again
 * would prove nothing the browser does not already hold, since it is already
 * unlocked. It is a guard against a misplaced click while sharing a screen, and
 * it is labelled as exactly that.
 */
async function reveal(key: string): Promise<void> {
    if (revealed.value.has(key)) {
        revealed.value.delete(key);
        revealed.value = new Set(revealed.value);

        return;
    }

    if (props.payload?.paranoid && confirming.value !== key) {
        confirming.value = key;

        // Focus follows the decision it is asking for. Leaving focus on the
        // reveal button means a keyboard user is told a question was asked and
        // given no way to reach it.
        await nextTick();
        confirmButton.value?.focus();

        return;
    }

    revealed.value = new Set(revealed.value).add(key);
    confirming.value = null;

    /*
     | The one thing the server cannot see, and the first question after any
     | compromise: which credentials did that session actually look at? A page
     | load fetches the whole vault's ciphertext whether one item is opened or
     | none, so only this tab knows.
     |
     | Reported once per item rather than once per field — the log records that
     | a secret was looked at, and turning one glance at a card into four
     | entries would make the feed less readable without saying anything more.
     |
     | Signed in the Worker and posted fire-and-forget. A failed report must
     | never stop a reveal: the secret was revealed either way, and an error over
     | a working feature teaches people to ignore errors.
     */
    if (revealed.value.size === 1) {
        reportReveal(crypto(), props.record.uuid);
    }
}
</script>

<template>
    <div :id="`secret-${record.uuid}`" class="p-4">
        <NoticePanel v-if="error" tone="accent" heading="integrity failure">{{ error }}</NoticePanel>

        <div v-else-if="payload" class="space-y-3">
            <div class="flex items-baseline justify-between gap-4">
                <div>
                    <p class="text-sm">{{ payload.key }}</p>
                    <p class="text-2xs tracking-[0.08em] text-faint uppercase">{{ typeLabel }}</p>
                </div>

                <div class="flex items-center gap-3 text-2xs">
                    <!--
                        Offered only where there is history, so the row does not
                        advertise a page that would tell the reader nothing. The
                        count is a plaintext column; what is in those versions is
                        as opaque to the server as everything else.
                    -->
                    <Link
                        v-if="record.historyCount > 0"
                        :href="`/secrets/${record.uuid}/history`"
                        class="text-muted hover:text-ink"
                        :aria-label="`View the ${record.historyCount} earlier version(s) of ${label}`"
                    >
                        history ({{ record.historyCount }})
                    </Link>
                    <button
                        v-if="canWrite"
                        type="button"
                        class="text-muted hover:text-ink"
                        :aria-label="`Share ${label} with a one-time link`"
                        @click="emit('share')"
                    >
                        share
                    </button>
                    <button
                        v-if="canWrite"
                        type="button"
                        class="text-muted hover:text-ink"
                        :aria-label="`Edit ${label}`"
                        @click="emit('edit')"
                    >
                        edit
                    </button>
                    <button
                        v-if="canWrite"
                        type="button"
                        class="text-muted hover:text-accent"
                        :aria-label="`Delete ${label}`"
                        @click="emit('remove')"
                    >
                        delete
                    </button>
                </div>
            </div>

            <NoticePanel v-if="confirming" tone="accent">
                This item is marked sensitive. Reveal it?
                <button
                    ref="confirmButton"
                    type="button"
                    class="ml-2 underline underline-offset-2"
                    @click="reveal(confirming)"
                >
                    show it
                </button>
            </NoticePanel>

            <SecretFieldValue
                v-for="entry in populated"
                :key="entry.field.key"
                :field="entry.field"
                :value="entry.value"
                :item-label="label"
                :revealed="revealed.has(entry.field.key)"
                @toggle="reveal(entry.field.key)"
            />

            <SecretFieldValue
                v-for="entry in unmapped"
                :key="entry.field.key"
                :field="entry.field"
                :value="entry.value"
                :item-label="label"
                :revealed="revealed.has(entry.field.key)"
                @toggle="reveal(entry.field.key)"
            />

            <p v-if="linkedLockboxName" class="text-2xs text-accent">
                <span aria-hidden="true">linked lockbox &rarr;</span>
                <span class="sr-only">Linked lockbox:</span>
                {{ linkedLockboxName }}
            </p>
        </div>
    </div>
</template>
