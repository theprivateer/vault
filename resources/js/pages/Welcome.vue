<script setup lang="ts">
import { Head } from '@inertiajs/vue3';

defineProps<{
    phase: string;
}>();
</script>

<template>
    <Head title="Welcome" />

    <main class="mx-auto flex min-h-full max-w-2xl flex-col justify-center gap-6 px-6 py-16">
        <div>
            <h1 class="text-2xl font-semibold tracking-tight">Vault</h1>
            <p class="mt-2 text-sm text-neutral-600">
                A zero-knowledge secret manager. The server stores ciphertext and wrapped keys, and never
                holds a key that can decrypt them.
            </p>
        </div>

        <p class="rounded-lg bg-neutral-100 px-4 py-3 font-mono text-xs text-neutral-700">
            {{ phase }}
        </p>
    </main>
</template>
