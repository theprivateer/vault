<script setup lang="ts">
import { useId } from 'vue';

defineProps<{
    label: string;
    type?: string | undefined;
    error?: string | undefined;
    hint?: string | undefined;
    autocomplete?: string | undefined;
    placeholder?: string | undefined;
    disabled?: boolean | undefined;
    autofocus?: boolean | undefined;
}>();

const model = defineModel<string>({ required: true });

const id = useId();
</script>

<template>
    <div>
        <label class="label" :for="id">{{ label }}</label>

        <input
            :id="id"
            v-model="model"
            class="field"
            :type="type ?? 'text'"
            :autocomplete="autocomplete"
            :placeholder="placeholder"
            :disabled="disabled"
            :autofocus="autofocus"
            :aria-invalid="error ? 'true' : undefined"
            :aria-describedby="error || hint ? `${id}-note` : undefined"
            spellcheck="false"
            autocapitalize="off"
        />

        <p v-if="error" :id="`${id}-note`" class="mt-1.5 text-2xs text-accent">{{ error }}</p>
        <p v-else-if="hint" :id="`${id}-note`" class="mt-1.5 text-2xs text-muted">{{ hint }}</p>
    </div>
</template>
