<script setup lang="ts">
defineProps<{
    title: string;
    subtitle?: string | undefined;
    step?: string | undefined;
}>();
</script>

<template>
    <div class="flex min-h-full flex-col">
        <header class="border-b border-line">
            <div class="mx-auto flex max-w-2xl items-baseline justify-between px-6 py-4">
                <span class="text-xs tracking-[0.2em] uppercase">vault</span>
                <span v-if="step" class="text-2xs tracking-[0.08em] text-muted uppercase">{{ step }}</span>
            </div>
        </header>

        <main class="mx-auto w-full max-w-2xl flex-1 px-6 py-12">
            <h1 class="text-base font-medium">{{ title }}</h1>
            <p v-if="subtitle" class="mt-1 max-w-prose text-sm text-muted">{{ subtitle }}</p>

            <div class="mt-8">
                <slot />
            </div>
        </main>

        <footer class="border-t border-line">
            <div class="mx-auto max-w-2xl px-6 py-4 text-2xs text-faint">
                the server stores ciphertext only &middot; it cannot read your secrets
            </div>
        </footer>
    </div>
</template>
