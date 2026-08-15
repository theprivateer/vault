<script setup lang="ts">
/**
 * The unlock prompt.
 *
 * Reached after any full page reload, which terminates the Worker and with it
 * the User Key. The bundle is already on the page, so unlocking is a single
 * Argon2id run and no round trip to the server.
 */
import { ref } from 'vue';

import NoticePanel from '@/components/NoticePanel.vue';
import TextField from '@/components/TextField.vue';
import { isIntegrityFailure } from '@/crypto/worker/client';
import { describeError } from '@/lib/errors';
import { useShared } from '@/lib/page';
import { unlock, useSession } from '@/stores/session';

const page = useShared();
const { state } = useSession();

const password = ref('');
const failure = ref('');

async function submit(): Promise<void> {
    failure.value = '';

    const bundle = page.props.auth.bundle;

    if (!bundle) {
        failure.value =
            'This account has no password wrapping, so it cannot be unlocked. ' +
            'Use your recovery kit to set a new password.';

        return;
    }

    try {
        await unlock(password.value, bundle, page.props.auth.identity, page.props.auth.pins);
        password.value = '';
    } catch (error) {
        /*
         | A wrong password and a tampered wrapping are indistinguishable here,
         | and deliberately so: both are an AEAD tag that did not verify. The
         | wording covers the likely case without asserting the other did not
         | happen.
         */
        if (isIntegrityFailure(error)) {
            failure.value = 'That password did not unlock your vault.';
        } else {
            failure.value = describeError(error, 'Your vault could not be unlocked.');
        }
    }
}
</script>

<template>
    <div class="max-w-sm">
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
</template>
