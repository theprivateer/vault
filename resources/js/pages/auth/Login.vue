<script setup lang="ts">
import { Head, Link, router } from '@inertiajs/vue3';
import { computed, ref } from 'vue';

import NoticePanel from '@/components/NoticePanel.vue';
import TextField from '@/components/TextField.vue';
import type { AadParams } from '@/crypto/aad';
import type { KdfParams } from '@/crypto/primitives';
import AuthLayout from '@/layouts/AuthLayout.vue';
import { fromBase64, toBase64 } from '@/lib/bytes';
import { HttpError, postJson } from '@/lib/http';
import { markAuthenticated, useSession } from '@/stores/session';

const email = ref('');
const password = ref('');
const totpCode = ref('');
const needsSecondFactor = ref(false);
const busy = ref(false);
const failure = ref('');

const { crypto: cryptoClient } = useSession();

const ready = computed(() => email.value.trim() !== '' && password.value !== '');

interface LoginResponse {
    redirect: string;
    bundle: { wrappedUserKey: string; userKeyAad: AadParams };
}

/**
 * Three steps, one password stretch.
 *
 *   1. Ask for the KDF salt. Answered for any address, real or not.
 *   2. Derive in the Worker; only the auth key comes out, and the KEK stays.
 *   3. Post the auth key. On success the server returns the wrapped User Key,
 *      which the Worker opens with the KEK it kept from step 2.
 *
 * Running Argon2id once rather than twice is the whole reason the Worker holds
 * the KEK between calls — at production parameters the second run would add
 * about three quarters of a second for no benefit.
 */
async function submit(): Promise<void> {
    failure.value = '';
    busy.value = true;

    try {
        const { kdfSalt, kdfParams } = await postJson<{ kdfSalt: string; kdfParams: KdfParams }>(
            '/auth/kdf-params',
            { email: email.value },
        );

        const authKey = await cryptoClient().beginUnlock({
            password: password.value,
            kdfSalt: fromBase64(kdfSalt),
            kdfParams,
        });

        const response = await postJson<LoginResponse>('/login', {
            email: email.value,
            auth_key: toBase64(authKey),
            totp_code: totpCode.value || null,
        });

        markAuthenticated();

        await cryptoClient().completeUnlock({
            wrappedUserKey: fromBase64(response.bundle.wrappedUserKey),
            userKeyAad: response.bundle.userKeyAad,
        });

        router.visit(response.redirect);
    } catch (cause) {
        /*
         | The server does not distinguish between an unknown address, a wrong
         | password and a wrong second factor, so neither can this. The
         | second-factor field is offered once, in case that is what is missing.
         */
        failure.value =
            cause instanceof HttpError
                ? (cause.first('email') ?? 'Those credentials do not match our records.')
                : 'Could not sign in. Please check your details and try again.';

        needsSecondFactor.value = true;
    } finally {
        busy.value = false;
    }
}
</script>

<template>
    <AuthLayout title="Sign in" subtitle="Your password is stretched here and never sent.">
        <Head title="Sign in" />

        <form class="max-w-sm space-y-6" @submit.prevent="submit">
            <TextField v-model="email" label="email" type="email" autocomplete="username" autofocus />

            <TextField
                v-model="password"
                label="master password"
                type="password"
                autocomplete="current-password"
            />

            <TextField
                v-if="needsSecondFactor"
                v-model="totpCode"
                label="two-factor code"
                autocomplete="one-time-code"
                hint="Six digits from your authenticator, or a backup code."
            />

            <NoticePanel v-if="failure" tone="accent">{{ failure }}</NoticePanel>

            <button type="submit" class="btn btn-primary" :disabled="!ready || busy">
                {{ busy ? 'unlocking…' : 'sign in' }}
            </button>

            <p v-if="busy" class="text-2xs text-muted">
                Stretching your password. Deliberately slow, and done here rather than on the server.
            </p>

            <hr class="rule" />

            <p class="text-2xs text-muted">
                Lost your password?
                <Link href="/recover" class="text-accent underline underline-offset-2">
                    use your recovery kit
                </Link>
            </p>
        </form>
    </AuthLayout>
</template>
