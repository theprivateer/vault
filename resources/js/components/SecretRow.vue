<script setup lang="ts">
/**
 * One secret, masked until asked for.
 *
 * The value is already decrypted and in memory by the time this renders —
 * masking is an interface courtesy against shoulder-surfing and screen sharing,
 * not a security boundary. Saying so plainly matters more than pretending
 * otherwise: anything that reaches this component has already been decrypted.
 */
import { ref } from 'vue';

import NoticePanel from '@/components/NoticePanel.vue';
import { copyForATime, CLIPBOARD_TTL_MS } from '@/lib/clipboard';
import type { SecretPayload, SecretRecord } from '@/lib/items';

const props = defineProps<{
    record: SecretRecord;
    payload: SecretPayload | null;
    error: string | null;
    linkedLockboxName: string | null;
    canWrite: boolean;
}>();

const emit = defineEmits<{ edit: []; remove: [] }>();

const revealed = ref(false);
const copied = ref(false);
const confirming = ref(false);

/**
 * `paranoid` items ask before revealing.
 *
 * A confirmation step, not a re-authentication: asking for the password again
 * would prove nothing the browser does not already hold, since it is already
 * unlocked. It is a guard against a misplaced click while sharing a screen,
 * and it is labelled as exactly that.
 */
function reveal(): void {
    if (props.payload?.paranoid && !revealed.value && !confirming.value) {
        confirming.value = true;

        return;
    }

    revealed.value = !revealed.value;
    confirming.value = false;
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
    <div class="p-4">
        <NoticePanel v-if="error" tone="accent" heading="integrity failure">{{ error }}</NoticePanel>

        <div v-else-if="payload" class="space-y-2">
            <div class="flex items-baseline justify-between gap-4">
                <div>
                    <p class="text-sm">{{ payload.key }}</p>
                    <p class="text-2xs tracking-[0.08em] text-faint uppercase">{{ payload.type }}</p>
                </div>

                <div class="flex items-center gap-3 text-2xs">
                    <button type="button" class="text-muted hover:text-ink" @click="reveal">
                        {{ revealed ? 'hide' : 'reveal' }}
                    </button>
                    <button type="button" class="text-muted hover:text-ink" @click="copy">
                        {{ copied ? 'copied' : 'copy' }}
                    </button>
                    <button
                        v-if="canWrite"
                        type="button"
                        class="text-muted hover:text-ink"
                        @click="emit('edit')"
                    >
                        edit
                    </button>
                    <button
                        v-if="canWrite"
                        type="button"
                        class="text-muted hover:text-accent"
                        @click="emit('remove')"
                    >
                        delete
                    </button>
                </div>
            </div>

            <NoticePanel v-if="confirming" tone="accent">
                This item is marked sensitive. Reveal it?
                <button type="button" class="ml-2 underline underline-offset-2" @click="reveal">
                    show it
                </button>
            </NoticePanel>

            <p class="text-sm break-all" :class="revealed ? '' : 'text-faint select-none'">
                {{ revealed ? payload.value : '••••••••••••' }}
            </p>

            <p v-if="copied" class="text-2xs text-muted">
                Cleared from the clipboard in {{ Math.round(CLIPBOARD_TTL_MS / 1000) }} seconds, if nothing
                else has copied since.
            </p>

            <p v-if="payload.url" class="text-2xs text-muted">{{ payload.url }}</p>
            <p v-if="payload.notes" class="text-2xs text-muted">{{ payload.notes }}</p>

            <p v-if="linkedLockboxName" class="text-2xs text-accent">
                linked lockbox &rarr; {{ linkedLockboxName }}
            </p>
        </div>
    </div>
</template>
