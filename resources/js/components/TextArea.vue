<script setup lang="ts">
/**
 * TextField's multi-line sibling, with the same API.
 *
 * Its absence was a real gap rather than a styling one: `note` and `key` were
 * offered as secret types while the only control in the application was a
 * single-line `<input>`, so neither could hold what its name promised — an SSH
 * private key or a note with a paragraph break could not be entered at all.
 */
import { useId } from 'vue';

defineProps<{
    label: string;
    error?: string | undefined;
    hint?: string | undefined;
    placeholder?: string | undefined;
    rows?: number | undefined;
    disabled?: boolean | undefined;
}>();

const model = defineModel<string>({ required: true });

const id = useId();
</script>

<template>
    <div>
        <label class="label" :for="id">{{ label }}</label>

        <textarea
            :id="id"
            v-model="model"
            class="field resize-y font-mono"
            :rows="rows ?? 5"
            :placeholder="placeholder"
            :disabled="disabled"
            :aria-invalid="error ? 'true' : undefined"
            :aria-describedby="error || hint ? `${id}-note` : undefined"
            spellcheck="false"
            autocapitalize="off"
        />

        <p v-if="error" :id="`${id}-note`" class="mt-1.5 text-2xs text-accent">{{ error }}</p>
        <p v-else-if="hint" :id="`${id}-note`" class="mt-1.5 text-2xs text-muted">{{ hint }}</p>
    </div>
</template>
