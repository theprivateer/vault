<script setup lang="ts">
withDefaults(
    defineProps<{
        tone?: 'neutral' | 'accent' | undefined;
        heading?: string | undefined;
    }>(),
    { tone: 'neutral' },
);
</script>

<template>
    <div
        class="border-l-2 px-4 py-3"
        :class="tone === 'accent' ? 'border-l-accent bg-accent-wash' : 'border-l-line-strong bg-sunken'"
    >
        <p
            v-if="heading"
            class="text-2xs tracking-[0.08em] uppercase"
            :class="tone === 'accent' ? 'text-accent' : ''"
        >
            {{ heading }}
        </p>
        <div class="max-w-prose text-sm" :class="heading ? 'mt-1.5' : ''">
            <slot />
        </div>
    </div>
</template>
