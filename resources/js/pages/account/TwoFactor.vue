<script setup lang="ts">
import { Link, router } from '@inertiajs/vue3';
import { ref } from 'vue';

import NoticePanel from '@/components/NoticePanel.vue';
import TextField from '@/components/TextField.vue';
import AppLayout from '@/layouts/AppLayout.vue';
import { HttpError, postJson } from '@/lib/http';
import { useDocumentTitle } from '@/lib/title';

defineProps<{
    enabled: boolean;
    secret?: string | undefined;
    groupedSecret?: string | undefined;
    uri?: string | undefined;
}>();

const code = ref('');
const busy = ref(false);
const failure = ref('');
const backupCodes = ref<string[]>([]);

async function confirm(): Promise<void> {
    failure.value = '';
    busy.value = true;

    try {
        const response = await postJson<{ backupCodes: string[] }>('/account/two-factor', {
            code: code.value,
        });

        backupCodes.value = response.backupCodes;
    } catch (cause) {
        failure.value =
            cause instanceof HttpError
                ? (cause.first('code') ?? cause.message)
                : 'Could not confirm that code.';
    } finally {
        busy.value = false;
    }
}

async function disable(): Promise<void> {
    busy.value = true;

    try {
        await postJson('/account/two-factor', { _method: 'DELETE' });
        router.reload();
    } finally {
        busy.value = false;
    }
}

useDocumentTitle('Two-factor authentication');
</script>

<template>
    <!-- Enrolment is an authentication concern; it needs no key material. -->
    <AppLayout :require-unlock="false">
        <div class="max-w-xl space-y-8">
            <div>
                <h1 class="text-base font-medium">Two-factor authentication</h1>
                <p class="mt-1 text-sm text-muted">A second factor for signing in.</p>
            </div>

            <NoticePanel heading="what this does and does not protect">
                This makes a stolen password less useful for obtaining a session. It does
                <em>not</em> stand between anyone and your secrets: unlocking your vault never involves the
                server, so a check the server performs cannot gate it. Your master password remains the thing
                that matters.
            </NoticePanel>

            <div v-if="backupCodes.length" class="space-y-4">
                <NoticePanel tone="accent" heading="backup codes — shown once">
                    Each of these works once, in place of a code from your authenticator. Only hashes are
                    stored, so they cannot be shown again.
                </NoticePanel>

                <ul class="panel divide-y divide-line">
                    <li
                        v-for="backupCode in backupCodes"
                        :key="backupCode"
                        class="px-4 py-2 text-sm select-all"
                    >
                        {{ backupCode }}
                    </li>
                </ul>

                <Link href="/vault" class="btn btn-primary">done</Link>
            </div>

            <div v-else-if="enabled" class="space-y-4">
                <p class="text-sm">Two-factor authentication is enabled on this account.</p>

                <button type="button" class="btn" :disabled="busy" @click="disable">
                    turn off two-factor
                </button>
            </div>

            <form v-else class="space-y-6" @submit.prevent="confirm">
                <div>
                    <p class="label">setup key</p>
                    <p class="text-sm break-all select-all">{{ groupedSecret }}</p>
                    <p class="mt-1.5 text-2xs text-muted">
                        Enter this in your authenticator app, or use the setup link below.
                    </p>
                </div>

                <div>
                    <p class="label">setup link</p>
                    <p class="text-2xs break-all text-muted select-all">{{ uri }}</p>
                </div>

                <hr class="rule" />

                <TextField
                    v-model="code"
                    label="confirmation code"
                    autocomplete="one-time-code"
                    hint="Six digits from your authenticator."
                    autofocus
                />

                <NoticePanel v-if="failure" tone="accent">{{ failure }}</NoticePanel>

                <button type="submit" class="btn btn-primary" :disabled="!code || busy">
                    {{ busy ? 'confirming…' : 'turn on two-factor' }}
                </button>
            </form>
        </div>
    </AppLayout>
</template>
