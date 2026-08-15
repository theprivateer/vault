<script setup lang="ts">
/**
 * An identity's fingerprint, as a picture and as characters.
 *
 * Both, always, and in that order for a reason. The picture is what people
 * actually notice changing; the characters are what they read out over the phone
 * when it matters. The picture encodes 56 bits and is a birthday problem, so
 * matching it is within reach of an attacker who cares — which is why it is
 * never shown alone and never described as the check.
 */
import { computed } from 'vue';

import { formatFingerprint } from '@/crypto/identity';
import { fromHex } from '@/lib/bytes';
import { IDENTICON_SIZE, identicon } from '@/lib/identicon';

const props = defineProps<{
    /** Lowercase hex, 64 characters. */
    fingerprint: string;
    label?: string | undefined;
}>();

const bytes = computed(() => fromHex(props.fingerprint));

const cells = computed(() => identicon(bytes.value));

const characters = computed(() => formatFingerprint(bytes.value));
</script>

<template>
    <div class="flex items-center gap-3">
        <!--
            aria-hidden, with the characters beside it carrying the meaning. A
            screen reader gets nothing from twenty-eight squares, and the value
            they encode is on the page already.
        -->
        <svg
            :viewBox="`0 0 ${IDENTICON_SIZE} ${IDENTICON_SIZE}`"
            class="size-10 shrink-0 bg-sunken"
            aria-hidden="true"
            focusable="false"
        >
            <rect
                v-for="cell in cells"
                :key="`${cell.x}-${cell.y}`"
                :x="cell.x"
                :y="cell.y"
                width="1"
                height="1"
                :class="cell.accent ? 'fill-accent' : 'fill-ink'"
            />
        </svg>

        <div>
            <p v-if="label" class="text-2xs tracking-[0.08em] text-faint uppercase">{{ label }}</p>
            <p class="text-xs tracking-[0.04em] break-all select-all">{{ characters }}</p>
        </div>
    </div>
</template>
