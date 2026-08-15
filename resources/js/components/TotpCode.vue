<script setup lang="ts">
/**
 * A live TOTP code, with the countdown that makes it usable.
 *
 * The seed lives inside `payload_ct` and has never been near the server. This
 * component turns it into the six digits somebody would otherwise be reading off
 * a phone, which is the entire feature: a credential that already lives here
 * should not require a second device to use.
 *
 * The countdown is not decoration. A code with four seconds left will be
 * rejected by the time it has been pasted, and every authenticator shows the
 * remaining time for that reason. The ring goes to the accent colour under ten
 * seconds so the warning does not depend on reading a number.
 */
import { computed, onUnmounted, ref, watch } from 'vue';

import { DEFAULT_TOTP, nowInSeconds, secondsRemaining, totp, type TotpConfig } from '@/crypto/totp';
import { copyForATime } from '@/lib/clipboard';
import { describeError } from '@/lib/errors';

const props = defineProps<{ secret: string; label: string }>();

const now = ref(nowInSeconds());
const copied = ref(false);

/**
 * Ticks four times a second rather than once.
 *
 * A one-second interval drifts against the wall clock, so the ring visibly
 * stalls or jumps at the rollover — and the rollover is the moment the number is
 * about to become wrong, which is exactly when it should look precise.
 */
const timer = window.setInterval(() => (now.value = nowInSeconds()), 250);

onUnmounted(() => window.clearInterval(timer));

const config = computed<TotpConfig>(() => ({ ...DEFAULT_TOTP, secret: props.secret }));

/**
 * The code, or the reason there isn't one.
 *
 * A malformed seed is reported rather than swallowed. A blank space where six
 * digits should be tells the user nothing, and the cause is almost always a seed
 * that lost characters when it was pasted.
 */
const code = computed<{ value: string; error: string }>(() => {
    try {
        return { value: totp(config.value, now.value), error: '' };
    } catch (error) {
        return { value: '', error: describeError(error, 'This one-time code could not be generated.') };
    }
});

const remaining = computed(() => secondsRemaining(now.value, config.value.period));

/** 0 to 1 through the current period, for the ring. */
const elapsed = computed(() => 1 - remaining.value / config.value.period);

const urgent = computed(() => remaining.value <= 10);

/** Grouped in threes, which is how every authenticator prints six digits. */
const grouped = computed(() =>
    code.value.value === '' ? '' : `${code.value.value.slice(0, 3)} ${code.value.value.slice(3)}`.trim(),
);

/*
 | Reset the "copied" flag when the code rolls over. Otherwise the interface
 | keeps claiming the clipboard holds this code after it has become a different
 | one, which is a small lie with a real cost — the user pastes an expired code.
 */
watch(code, () => (copied.value = false));

async function copy(): Promise<void> {
    if (code.value.value === '') {
        return;
    }

    await copyForATime(code.value.value);
    copied.value = true;
}
</script>

<template>
    <div class="flex items-center gap-3">
        <template v-if="code.error === ''">
            <!--
                aria-live="polite" rather than "assertive": the code changes
                every thirty seconds and an assertive region would interrupt a
                screen reader mid-sentence, twice a minute, forever.
            -->
            <p class="text-sm tracking-[0.2em] tabular-nums" aria-live="polite">{{ grouped }}</p>

            <svg
                class="h-3 w-3 shrink-0"
                viewBox="0 0 20 20"
                role="img"
                :aria-label="`${remaining} seconds until this code changes`"
            >
                <circle
                    cx="10"
                    cy="10"
                    r="9"
                    fill="none"
                    stroke="currentColor"
                    stroke-width="2"
                    class="text-line"
                />
                <circle
                    cx="10"
                    cy="10"
                    r="9"
                    fill="none"
                    stroke="currentColor"
                    stroke-width="2"
                    :class="urgent ? 'text-accent' : 'text-muted'"
                    :stroke-dasharray="`${(1 - elapsed) * 56.5} 56.5`"
                    transform="rotate(-90 10 10)"
                />
            </svg>

            <button
                type="button"
                class="text-2xs text-muted hover:text-ink"
                :aria-label="`Copy the one-time code for ${label}`"
                @click="copy"
            >
                {{ copied ? 'copied' : 'copy code' }}
            </button>
        </template>

        <p v-else class="text-2xs text-accent">{{ code.error }}</p>
    </div>
</template>
