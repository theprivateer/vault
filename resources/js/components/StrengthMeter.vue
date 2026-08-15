<script setup lang="ts">
/**
 * How strong a password somebody typed appears to be.
 *
 * **This is an estimate, and a weaker one than a dictionary-backed tool would
 * give.** zxcvbn was the specified option and was declined: three packages and
 * several hundred kilobytes of dictionaries against a threat model that names a
 * small dependency surface as a defence (A10). What is here catches structure —
 * repeats, runs, keyboard patterns, dates, the handful of passwords at the top
 * of every leak — and misses dictionary words and names entirely.
 *
 * So the component says so. A meter that overstates is worse than no meter,
 * because it converts a vague unease into false confidence, and the one thing
 * this application should never do is tell somebody a password is fine when it
 * is a pet's name with a year after it.
 */
import { computed } from 'vue';

import { estimateStrength } from '@/lib/strength';

const props = defineProps<{ password: string }>();

const strength = computed(() => estimateStrength(props.password));

/** Capped at 100 bits for the bar; beyond that the difference is academic. */
const width = computed(() => Math.min(100, strength.value.bits));
</script>

<template>
    <div v-if="password !== ''" class="space-y-1">
        <div class="h-px w-full bg-line">
            <div
                class="h-px"
                :class="strength.score >= 3 ? 'bg-accent' : 'bg-muted'"
                :style="{ width: `${width}%` }"
            />
        </div>

        <p class="text-2xs text-muted" role="status">
            <span class="text-ink">{{ strength.label }}</span>
            &middot; about {{ Math.round(strength.bits) }} bits, estimated
        </p>

        <p v-for="warning in strength.warnings" :key="warning" class="text-2xs text-accent">
            {{ warning }}
        </p>

        <!--
            The limit, stated where the number is. Only shown once the password
            is long enough for the score to start looking reassuring, which is
            when the omission starts to matter.
        -->
        <p v-if="strength.score >= 2" class="text-2xs text-faint">
            Estimated without a dictionary — a real word or name scores higher here than it deserves.
            Generated passwords carry an exact figure instead.
        </p>
    </div>
</template>
