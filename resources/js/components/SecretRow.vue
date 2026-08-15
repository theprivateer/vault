<script setup lang="ts">
/**
 * One secret, masked until asked for.
 *
 * The value is already decrypted and in memory by the time this renders —
 * masking is an interface courtesy against shoulder-surfing and screen sharing,
 * not a security boundary. Saying so plainly matters more than pretending
 * otherwise: anything that reaches this component has already been decrypted.
 *
 * **Masking and screen readers.** A row of bullet characters is nonsense read
 * aloud, and worse, a naive mask leaks the length of the password to anyone
 * counting dots. So the mask is a fixed-width run marked `aria-hidden`, with
 * the real state announced in words beside it — and when the value is revealed,
 * the announcement says so, because someone using a screen reader in a shared
 * room deserves to know their password is now on screen.
 */
import { computed, nextTick, ref, useId } from 'vue';

import NoticePanel from '@/components/NoticePanel.vue';
import { reportReveal } from '@/lib/audit';
import { copyForATime, CLIPBOARD_TTL_MS } from '@/lib/clipboard';
import type { SecretPayload, SecretRecord } from '@/lib/items';
import { useSession } from '@/stores/session';

const props = defineProps<{
    record: SecretRecord;
    payload: SecretPayload | null;
    error: string | null;
    linkedLockboxName: string | null;
    canWrite: boolean;
}>();

const emit = defineEmits<{ edit: []; remove: [] }>();

const { crypto } = useSession();

const revealed = ref(false);
const copied = ref(false);
const confirming = ref(false);
const valueId = useId();
const value = ref<HTMLParagraphElement | null>(null);
const confirmButton = ref<HTMLButtonElement | null>(null);

/** A fixed run: a mask as long as the password would announce its length. */
const MASK = '••••••••••••';

const label = computed(() => props.payload?.key ?? 'this secret');

/**
 * `paranoid` items ask before revealing.
 *
 * A confirmation step, not a re-authentication: asking for the password again
 * would prove nothing the browser does not already hold, since it is already
 * unlocked. It is a guard against a misplaced click while sharing a screen,
 * and it is labelled as exactly that.
 */
async function reveal(): Promise<void> {
    if (props.payload?.paranoid && !revealed.value && !confirming.value) {
        confirming.value = true;

        // Focus follows the decision it is asking for. Leaving focus on the
        // reveal button means a keyboard user is told a question was asked and
        // given no way to reach it.
        await nextTick();
        confirmButton.value?.focus();

        return;
    }

    revealed.value = !revealed.value;
    confirming.value = false;

    if (revealed.value) {
        /*
         | The one thing the server cannot see, and the first question after any
         | compromise: which credentials did that session actually look at? A
         | page load fetches the whole vault's ciphertext whether one item is
         | opened or none, so only this tab knows.
         |
         | Signed in the Worker and posted fire-and-forget. A failed report must
         | never stop a reveal — the secret was revealed either way, and an
         | error over a working feature teaches people to ignore errors.
         */
        reportReveal(crypto(), props.record.uuid);

        await nextTick();
        value.value?.focus();
    }
}

async function copy(): Promise<void> {
    if (!props.payload) {
        return;
    }

    await copyForATime(props.payload.value);

    copied.value = true;
    setTimeout(() => (copied.value = false), 2_000);
}
</script>

<template>
    <div :id="`secret-${record.uuid}`" class="p-4">
        <NoticePanel v-if="error" tone="accent" heading="integrity failure">{{ error }}</NoticePanel>

        <div v-else-if="payload" class="space-y-2">
            <div class="flex items-baseline justify-between gap-4">
                <div>
                    <p class="text-sm">{{ payload.key }}</p>
                    <p class="text-2xs tracking-[0.08em] text-faint uppercase">{{ payload.type }}</p>
                </div>

                <div class="flex items-center gap-3 text-2xs">
                    <button
                        type="button"
                        class="text-muted hover:text-ink"
                        :aria-expanded="revealed"
                        :aria-controls="valueId"
                        :aria-label="`${revealed ? 'Hide' : 'Reveal'} the value of ${label}`"
                        @click="reveal"
                    >
                        {{ revealed ? 'hide' : 'reveal' }}
                    </button>
                    <button
                        type="button"
                        class="text-muted hover:text-ink"
                        :aria-label="`Copy the value of ${label} to the clipboard`"
                        @click="copy"
                    >
                        {{ copied ? 'copied' : 'copy' }}
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
                    @click="reveal"
                >
                    show it
                </button>
            </NoticePanel>

            <!--
                tabindex="-1" so focus can be moved here on reveal without
                putting the paragraph into the tab order, which would make
                every secret an extra stop on the way down the page.
            -->
            <p
                :id="valueId"
                ref="value"
                tabindex="-1"
                class="text-sm break-all"
                :class="revealed ? '' : 'text-faint select-none'"
            >
                <span v-if="revealed">{{ payload.value }}</span>
                <template v-else>
                    <span aria-hidden="true">{{ MASK }}</span>
                    <span class="sr-only">Value hidden. Use the reveal button to show it.</span>
                </template>
            </p>

            <p v-if="revealed" class="sr-only" role="status">
                The value of {{ label }} is now visible on screen.
            </p>

            <p v-if="copied" class="text-2xs text-muted" role="status">
                Cleared from the clipboard in {{ Math.round(CLIPBOARD_TTL_MS / 1000) }} seconds, if nothing
                else has copied since.
            </p>

            <p v-if="payload.url" class="text-2xs text-muted">{{ payload.url }}</p>
            <p v-if="payload.notes" class="text-2xs text-muted">{{ payload.notes }}</p>

            <p v-if="linkedLockboxName" class="text-2xs text-accent">
                <span aria-hidden="true">linked lockbox &rarr;</span>
                <span class="sr-only">Linked lockbox:</span>
                {{ linkedLockboxName }}
            </p>
        </div>
    </div>
</template>
