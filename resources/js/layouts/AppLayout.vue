<script setup lang="ts">
import { Link, router } from '@inertiajs/vue3';
import { onBeforeUnmount, onMounted, ref } from 'vue';

import CommandPalette from '@/components/CommandPalette.vue';
import UnlockPanel from '@/components/UnlockPanel.vue';
import { useShared } from '@/lib/page';
import { installLockGuards, lock, markAuthenticated, signOut, useSession } from '@/stores/session';

/**
 * `requireUnlock` gates the page content behind the unlock prompt. Pages that
 * are genuinely usable while locked — account settings, second-factor
 * enrolment — opt out. Anything showing vault data must not.
 */
const { requireUnlock = true } = defineProps<{ requireUnlock?: boolean }>();

const page = useShared();

const { state, isUnlocked } = useSession();

let detach: (() => void) | null = null;

const palette = ref<InstanceType<typeof CommandPalette> | null>(null);

markAuthenticated();

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
                <Link href="/vaults" class="text-xs tracking-[0.2em] uppercase">vault</Link>

                <div class="flex items-center gap-4 text-2xs">
                    <!--
                        The glyph carries the state as well as the colour: a
                        status told only in orange is no status at all to
                        anyone who cannot distinguish it, and the word is read
                        aloud by a screen reader either way.
                    -->
                    <span
                        class="tracking-[0.08em] uppercase"
                        :class="isUnlocked ? 'text-accent' : 'text-muted'"
                        role="status"
                    >
                        <span aria-hidden="true">{{ isUnlocked ? '●' : '○' }}</span>
                        {{ isUnlocked ? 'unlocked' : 'locked' }}
                    </span>

                    <button
                        v-if="isUnlocked"
                        type="button"
                        class="text-muted hover:text-ink"
                        @click="palette?.show()"
                    >
                        search <kbd class="text-faint">/</kbd>
                    </button>

                    <span v-if="page.props.auth.user" class="text-muted">
                        {{ page.props.auth.user.handle }}
                    </span>

                    <Link href="/account/activity" class="text-muted hover:text-ink">activity</Link>
                    <Link href="/account/two-factor" class="text-muted hover:text-ink">account</Link>

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
            <UnlockPanel v-if="requireUnlock && !isUnlocked" />
            <slot v-else />
        </main>

        <CommandPalette ref="palette" />

        <footer class="border-t border-line">
            <div class="mx-auto flex max-w-5xl justify-between gap-4 px-6 py-4 text-2xs text-faint">
                <span>the server stores ciphertext only &middot; it cannot read your secrets</span>
                <span v-if="state.lockReason === 'idle'">locked after inactivity</span>
            </div>
        </footer>
    </div>
</template>
