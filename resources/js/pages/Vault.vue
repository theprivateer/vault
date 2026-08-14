<script setup lang="ts">
import { Head, Link } from '@inertiajs/vue3';
import { ref } from 'vue';

import NoticePanel from '@/components/NoticePanel.vue';
import TextField from '@/components/TextField.vue';
import AppLayout from '@/layouts/AppLayout.vue';
import { isIntegrityFailure } from '@/crypto/worker/client';
import { markAuthenticated, unlock, useSession, type UnlockBundle } from '@/stores/session';

const props = defineProps<{
    bundle: UnlockBundle;
    identity: { fingerprint: string } | null;
    twoFactorEnabled: boolean;
}>();

const { state, isUnlocked } = useSession();

const password = ref('');
const failure = ref('');

markAuthenticated();

/**
 * Reached after a full page reload, which terminates the Worker and with it the
 * User Key. The bundle is already on the page, so this is a single Argon2id run
 * and no round trip.
 */
async function submit(): Promise<void> {
    failure.value = '';

    try {
        await unlock(password.value, props.bundle);
        password.value = '';
    } catch (error) {
        failure.value = isIntegrityFailure(error)
            ? 'That password did not unlock your vault.'
            : 'Something went wrong unlocking your vault.';
    }
}
</script>

<template>
    <AppLayout>
        <Head title="Vault" />

        <div v-if="!isUnlocked" class="max-w-sm">
            <h1 class="text-base font-medium">Vault locked</h1>
            <p class="mt-1 text-sm text-muted">
                {{
                    state.lockReason === 'idle'
                        ? 'Locked after a period of inactivity.'
                        : 'Enter your master password to unlock.'
                }}
            </p>

            <form class="mt-8 space-y-6" @submit.prevent="submit">
                <TextField
                    v-model="password"
                    label="master password"
                    type="password"
                    autocomplete="current-password"
                    autofocus
                />

                <NoticePanel v-if="failure" tone="accent">{{ failure }}</NoticePanel>

                <button type="submit" class="btn btn-primary" :disabled="!password || state.unlocking">
                    {{ state.unlocking ? 'unlocking…' : 'unlock' }}
                </button>
            </form>
        </div>

        <div v-else class="space-y-8">
            <div>
                <h1 class="text-base font-medium">Your vaults</h1>
                <p class="mt-1 text-sm text-muted">
                    Nothing here yet — vaults, lockboxes and secrets arrive in the next phase.
                </p>
            </div>

            <div class="panel divide-y divide-line">
                <div class="flex items-baseline justify-between gap-4 p-4">
                    <div>
                        <p class="text-2xs tracking-[0.08em] text-muted uppercase">key fingerprint</p>
                        <p class="mt-1 text-sm break-all">{{ identity?.fingerprint ?? '—' }}</p>
                    </div>
                </div>

                <div class="flex items-baseline justify-between gap-4 p-4">
                    <div>
                        <p class="text-2xs tracking-[0.08em] text-muted uppercase">two-factor</p>
                        <p class="mt-1 text-sm">
                            {{ twoFactorEnabled ? 'enabled' : 'not enabled' }}
                        </p>
                    </div>
                    <Link
                        href="/account/two-factor"
                        class="text-2xs text-accent underline underline-offset-2"
                    >
                        {{ twoFactorEnabled ? 'manage' : 'set up' }}
                    </Link>
                </div>
            </div>

            <NoticePanel heading="what the server can see">
                Timestamps, sizes and the shape of your data. Not names, not values, not filenames. A
                compromised server can still serve modified JavaScript to this page — that is the limit of
                browser-delivered encryption, and no amount of cryptography here removes it.
            </NoticePanel>
        </div>
    </AppLayout>
</template>
