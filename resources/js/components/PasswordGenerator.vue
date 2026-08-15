<script setup lang="ts">
/**
 * Generating a password or passphrase, with an entropy figure that means
 * something.
 *
 * The distinction this component exists to keep visible: for a value it just
 * generated, the bits are **arithmetic** — the process is known, so
 * log2(alphabet) × length is exactly right. For a value somebody typed, the bits
 * are an **estimate**, and a weaker one than a dictionary-backed tool would give.
 * Those two numbers look identical on a progress bar, so the wording beside them
 * does the work the bar cannot.
 */
import { computed, ref, watch } from 'vue';

import { copyForATime } from '@/lib/clipboard';
import { describeError } from '@/lib/errors';
import {
    CHARACTER_CLASSES,
    generatePassphrase,
    generatePassword,
    MAX_PASSPHRASE_WORDS,
    MAX_PASSWORD_LENGTH,
    MIN_PASSPHRASE_WORDS,
    MIN_PASSWORD_LENGTH,
    type CharacterClass,
    type Generated,
} from '@/lib/generate';
import { STRENGTH_LABELS } from '@/lib/strength';

const emit = defineEmits<{ use: [value: string] }>();

type Mode = 'password' | 'passphrase';

const mode = ref<Mode>('password');
const length = ref(20);
const words = ref(5);
const excludeAmbiguous = ref(false);
const appendNumber = ref(false);
const classes = ref<CharacterClass[]>(['lower', 'upper', 'digits', 'symbols']);
const generated = ref<Generated | null>(null);
const failure = ref('');
const copied = ref(false);

const CLASS_LABELS: Record<CharacterClass, string> = {
    lower: 'a–z',
    upper: 'A–Z',
    digits: '0–9',
    symbols: '!#$…',
};

const CLASS_NAMES = Object.keys(CHARACTER_CLASSES) as CharacterClass[];

/**
 * The score band, borrowed from the estimator purely so the bar reads the same
 * either way. The *number* is still the exact one, not an estimate — running a
 * generated password back through `estimateStrength` would penalise it for
 * accidental repeats it is entitled to have.
 */
const band = computed(() => {
    const bits = generated.value?.bits ?? 0;

    return [28, 40, 60, 80].filter((threshold) => bits >= threshold).length;
});

const label = computed(() => STRENGTH_LABELS[band.value] ?? 'very weak');

watch([mode, length, words, excludeAmbiguous, appendNumber, classes], () => regenerate(), {
    deep: true,
});

function regenerate(): void {
    failure.value = '';
    copied.value = false;

    try {
        generated.value =
            mode.value === 'password'
                ? generatePassword({
                      length: length.value,
                      classes: classes.value,
                      excludeAmbiguous: excludeAmbiguous.value,
                  })
                : generatePassphrase({
                      words: words.value,
                      appendNumber: appendNumber.value,
                  });
    } catch (error) {
        generated.value = null;
        failure.value = describeError(error, 'Nothing could be generated from those settings.');
    }
}

function toggleClass(name: CharacterClass): void {
    classes.value = classes.value.includes(name)
        ? classes.value.filter((existing) => existing !== name)
        : [...classes.value, name];
}

async function copy(): Promise<void> {
    if (!generated.value) {
        return;
    }

    await copyForATime(generated.value.value);
    copied.value = true;
}

regenerate();
</script>

<template>
    <div class="panel space-y-6 p-4">
        <div class="flex items-baseline justify-between gap-4">
            <h3 class="text-sm">generate</h3>

            <div class="flex gap-3 text-2xs">
                <button
                    v-for="option in ['password', 'passphrase'] as Mode[]"
                    :key="option"
                    type="button"
                    :class="mode === option ? 'text-ink' : 'text-muted hover:text-ink'"
                    :aria-pressed="mode === option"
                    @click="mode = option"
                >
                    {{ option }}
                </button>
            </div>
        </div>

        <div v-if="generated" class="space-y-2">
            <p class="text-sm break-all" aria-live="polite">{{ generated.value }}</p>

            <div class="h-px w-full bg-line">
                <div
                    class="h-px"
                    :class="band >= 3 ? 'bg-accent' : 'bg-muted'"
                    :style="{ width: `${Math.min(100, (generated.bits / 100) * 100)}%` }"
                />
            </div>

            <p class="text-2xs text-muted">
                <span class="text-ink">{{ Math.round(generated.bits) }} bits</span> &middot;
                {{ label }} &middot; {{ generated.describe }}
            </p>

            <!--
                The claim that separates this number from the one under a typed
                password. Worth the line: they are displayed identically and mean
                genuinely different things.
            -->
            <p class="text-2xs text-faint">
                Exact, not estimated — this was drawn uniformly at random, so the arithmetic is the whole
                story.
            </p>
        </div>

        <p v-if="failure" class="text-2xs text-accent">{{ failure }}</p>

        <div v-if="mode === 'password'" class="space-y-4">
            <div>
                <label class="label" for="generate-length">length &middot; {{ length }}</label>
                <input
                    id="generate-length"
                    v-model.number="length"
                    type="range"
                    :min="MIN_PASSWORD_LENGTH"
                    :max="MAX_PASSWORD_LENGTH"
                    class="w-full"
                />
            </div>

            <div class="flex flex-wrap gap-3 text-2xs">
                <button
                    v-for="name in CLASS_NAMES"
                    :key="name"
                    type="button"
                    :class="classes.includes(name) ? 'text-ink' : 'text-muted hover:text-ink'"
                    :aria-pressed="classes.includes(name)"
                    @click="toggleClass(name)"
                >
                    {{ CLASS_LABELS[name] }}
                </button>
            </div>

            <label class="flex items-center gap-2 text-2xs text-muted">
                <input v-model="excludeAmbiguous" type="checkbox" />
                avoid characters that look alike (l, 1, O, 0)
            </label>
        </div>

        <div v-else class="space-y-4">
            <div>
                <label class="label" for="generate-words">words &middot; {{ words }}</label>
                <input
                    id="generate-words"
                    v-model.number="words"
                    type="range"
                    :min="MIN_PASSPHRASE_WORDS"
                    :max="MAX_PASSPHRASE_WORDS"
                    class="w-full"
                />
            </div>

            <label class="flex items-center gap-2 text-2xs text-muted">
                <input v-model="appendNumber" type="checkbox" />
                add a digit, for policies that demand one
            </label>

            <p class="text-2xs text-faint">
                Words are drawn from the EFF list of 7,776, bundled with the application — nothing is fetched,
                because the content policy forbids it and because asking a third party for a wordlist tells
                them when somebody is making a credential.
            </p>
        </div>

        <div class="flex gap-3">
            <button type="button" class="btn" @click="regenerate">another</button>
            <button type="button" class="btn" :disabled="!generated" @click="copy">
                {{ copied ? 'copied' : 'copy' }}
            </button>
            <button
                type="button"
                class="btn btn-primary"
                :disabled="!generated"
                @click="generated && emit('use', generated.value)"
            >
                use this
            </button>
        </div>
    </div>
</template>
