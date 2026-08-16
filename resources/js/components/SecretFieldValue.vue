<script setup lang="ts">
/**
 * One field of a secret, in display mode, rendered from its schema entry.
 *
 * **Masking is an interface courtesy, not a boundary.** Anything reaching this
 * component was decrypted before it got here; hiding it defends against a
 * shoulder and a screen share, and nothing else. What the schema's `sensitive`
 * flag really decides is which fields get a reveal step and a clipboard that
 * clears itself — so a cardholder's name reads at a glance while the number
 * beside it does not.
 *
 * **Masking and screen readers.** A row of bullets is nonsense read aloud, and a
 * naive mask leaks the value's length to anyone counting dots. So the mask is a
 * fixed-width run marked `aria-hidden`, with the state announced in words beside
 * it — and when a value is revealed the announcement says so, because somebody
 * using a screen reader in a shared room deserves to know it is now on screen.
 */
import { ref } from 'vue';

import TotpCode from '@/components/TotpCode.vue';
import { copyForATime, CLIPBOARD_TTL_MS } from '@/lib/clipboard';
import type { SecretField } from '@/lib/secretTypes';

const props = defineProps<{
    field: SecretField;
    value: string;
    /** The item's name, so an announcement says which secret it belongs to. */
    itemLabel: string;
    revealed: boolean;
}>();

const emit = defineEmits<{ toggle: [] }>();

const copied = ref(false);

/** A fixed run: a mask as long as the value would announce its length. */
const MASK = '••••••••••••';

async function copy(): Promise<void> {
    await copyForATime(props.value);

    copied.value = true;
    setTimeout(() => (copied.value = false), 2_000);
}
</script>

<template>
    <div>
        <!--
            The one-time code, generated here from a seed that has never left
            this browser. Shown without a reveal step: a code is worth thirty
            seconds and is useless without the password it accompanies, so
            hiding it would be ceremony rather than protection. The seed behind
            it is never rendered at all.
        -->
        <TotpCode v-if="field.control === 'totp'" :secret="value" :label="itemLabel" />

        <template v-else>
            <div class="flex items-baseline justify-between gap-4">
                <p class="text-2xs tracking-[0.08em] text-faint uppercase">{{ field.label }}</p>

                <div class="flex items-center gap-3 text-2xs">
                    <button
                        v-if="field.sensitive"
                        type="button"
                        class="text-muted hover:text-ink"
                        :aria-expanded="revealed"
                        :aria-label="`${revealed ? 'Hide' : 'Reveal'} the ${field.label} of ${itemLabel}`"
                        @click="emit('toggle')"
                    >
                        {{ revealed ? 'hide' : 'reveal' }}
                    </button>
                    <button
                        type="button"
                        class="text-muted hover:text-ink"
                        :aria-label="`Copy the ${field.label} of ${itemLabel} to the clipboard`"
                        @click="copy"
                    >
                        {{ copied ? 'copied' : 'copy' }}
                    </button>
                </div>
            </div>

            <p
                class="text-sm break-all"
                :class="[
                    !field.sensitive || revealed ? '' : 'text-faint select-none',
                    field.control === 'textarea' ? 'whitespace-pre-wrap' : '',
                ]"
            >
                <span v-if="!field.sensitive || revealed">{{ value }}</span>
                <template v-else>
                    <span aria-hidden="true">{{ MASK }}</span>
                    <span class="sr-only">Hidden. Use the reveal button to show it.</span>
                </template>
            </p>

            <p v-if="field.sensitive && revealed" class="sr-only" role="status">
                The {{ field.label }} of {{ itemLabel }} is now visible on screen.
            </p>

            <p v-if="copied" class="text-2xs text-muted" role="status">
                Cleared from the clipboard in {{ Math.round(CLIPBOARD_TTL_MS / 1000) }} seconds, if nothing
                else has copied since.
            </p>
        </template>
    </div>
</template>
