<script setup lang="ts">
import { Link, router, usePage } from '@inertiajs/vue3';
import { onBeforeUnmount, onMounted } from 'vue';

import { installLockGuards, lock, signOut, useSession } from '@/stores/session';

const page = usePage<{ auth: { user: { display_name: string; handle: string } | null } }>();

const { state, isUnlocked } = useSession();

let detach: (() => void) | null = null;

onMounted(() => {
    detach = installLockGuards();
});

onBeforeUnmount(() => detach?.());

function signOutNow(): void {
    signOut();
    router.post('/logout');
}
</script>

<template>
    <div class="flex min-h-full flex-col">
        <header class="border-b border-line">
            <div class="mx-auto flex max-w-5xl items-center justify-between gap-4 px-6 py-4">
                <Link href="/vault" class="text-xs tracking-[0.2em] uppercase">vault</Link>

                <div class="flex items-center gap-4 text-2xs">
                    <span
                        class="tracking-[0.08em] uppercase"
                        :class="isUnlocked ? 'text-accent' : 'text-muted'"
                    >
                        {{ isUnlocked ? '● unlocked' : '○ locked' }}
                    </span>

                    <span v-if="page.props.auth.user" class="text-muted">
                        {{ page.props.auth.user.handle }}
                    </span>

                    <button
                        v-if="isUnlocked"
                        type="button"
                        class="text-muted hover:text-ink"
                        @click="lock('manual')"
                    >
                        lock
                    </button>

                    <button type="button" class="text-muted hover:text-ink" @click="signOutNow">
                        sign out
                    </button>
                </div>
            </div>
        </header>

        <main class="mx-auto w-full max-w-5xl flex-1 px-6 py-10">
            <slot />
        </main>

        <footer class="border-t border-line">
            <div class="mx-auto flex max-w-5xl justify-between gap-4 px-6 py-4 text-2xs text-faint">
                <span>the server stores ciphertext only &middot; it cannot read your secrets</span>
                <span v-if="state.lockReason === 'idle'">locked after inactivity</span>
            </div>
        </footer>
    </div>
</template>
