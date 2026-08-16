<script setup lang="ts">
import { Link, router } from '@inertiajs/vue3';
import { computed, ref } from 'vue';

import NoticePanel from '@/components/NoticePanel.vue';
import RecoveryKit from '@/components/RecoveryKit.vue';
import TextField from '@/components/TextField.vue';
import type { AadParams } from '@/crypto/aad';
import type { KdfParams } from '@/crypto/primitives';
import AuthLayout from '@/layouts/AuthLayout.vue';
import { fromBase64, toBase64 } from '@/lib/bytes';
import { describeError } from '@/lib/errors';
import { HttpError, postJson } from '@/lib/http';
import { markAuthenticated, useSession } from '@/stores/session';
import { useDocumentTitle } from '@/lib/title';

const props = defineProps<{ kdfParams: KdfParams }>();

type Step = 'code' | 'password' | 'kit';

const step = ref<Step>('code');
const busy = ref(false);
const failure = ref('');

const email = ref('');
const recoveryCode = ref('');
const password = ref('');
const passwordConfirmation = ref('');
const newRecoveryCode = ref('');

const { crypto: cryptoClient } = useSession();

const passwordsMatch = computed(
    () => password.value.length > 0 && password.value === passwordConfirmation.value,
);

let userKeyAad: AadParams | null = null;

/**
 * The recovery code is split here, exactly as the password is: the auth key
 * goes to the server to prove possession, the KEK stays and does the unwrapping.
 * The server never sees the code, and cannot open the wrapping it holds.
 */
async function useRecoveryCode(): Promise<void> {
    failure.value = '';
    busy.value = true;

    try {
        const { recoverySalt } = await postJson<{ recoverySalt: string }>('/recover/salt', {
            email: email.value,
        });

        // Derived in the Worker, which keeps the KEK and returns only the auth
        // key. The recovery code is split exactly as the password is.
        const authKey = await cryptoClient().beginRecovery({
            recoveryCode: recoveryCode.value,
            recoverySalt: fromBase64(recoverySalt),
        });

        const verified = await postJson<{ wrappedUserKey: string; userKeyAad: AadParams }>('/recover', {
            email: email.value,
            recovery_auth_key: toBase64(authKey),
        });

        userKeyAad = verified.userKeyAad;

        await cryptoClient().completeUnlock({
            wrappedUserKey: fromBase64(verified.wrappedUserKey),
            userKeyAad: verified.userKeyAad,
        });

        markAuthenticated();
        step.value = 'password';
    } catch (error) {
        failure.value =
            error instanceof HttpError
                ? (error.first('recovery_code') ?? error.first('email') ?? error.message)
                : describeError(error, 'That email and recovery kit combination did not work.');
    } finally {
        busy.value = false;
    }
}

/**
 * Recovery forces a new password, and issues a new kit in the same step: the
 * old code has by now been typed into a browser, and may be in a clipboard, a
 * screenshot or a password manager.
 */
async function setNewPassword(): Promise<void> {
    if (!userKeyAad) {
        return;
    }

    failure.value = '';
    busy.value = true;

    try {
        const kdfSalt = crypto.getRandomValues(new Uint8Array(16));

        const rewrapped = await cryptoClient().rewrapForPassword({
            password: password.value,
            kdfSalt,
            kdfParams: props.kdfParams,
            userKeyAad,
        });

        const kit = await cryptoClient().issueRecoveryKit(userKeyAad);

        await postJson('/account/password', {
            kdf_salt: toBase64(kdfSalt),
            kdf_params: props.kdfParams,
            auth_key: toBase64(rewrapped.authKey),
            wrapped_user_key: toBase64(rewrapped.wrappedUserKey),
            recovery_salt: toBase64(kit.recoverySalt),
            recovery_wrapped_user_key: toBase64(kit.recoveryWrappedUserKey),
            recovery_auth_key: toBase64(kit.recoveryAuthKey),
        });

        newRecoveryCode.value = kit.recoveryCode;
        step.value = 'kit';
    } catch (error) {
        failure.value = describeError(error, 'Could not set your new password.');
    } finally {
        busy.value = false;
    }
}

useDocumentTitle('Recover your account');
</script>

<template>
    <AuthLayout
        title="Recover your account"
        :subtitle="
            step === 'code'
                ? 'Your recovery kit is used here, in this browser. It is never sent to the server.'
                : undefined
        "
    >
        <RecoveryKit
            v-if="step === 'kit'"
            :code="newRecoveryCode"
            :email="email"
            @acknowledged="router.visit('/vaults')"
        />

        <form v-else-if="step === 'password'" class="max-w-sm space-y-6" @submit.prevent="setNewPassword">
            <NoticePanel tone="accent" heading="recovery kit accepted">
                Choose a new master password. You will be issued a fresh recovery kit, because the one you
                just used has been typed into a browser.
            </NoticePanel>

            <TextField
                v-model="password"
                label="new master password"
                type="password"
                autocomplete="new-password"
                autofocus
            />

            <TextField
                v-model="passwordConfirmation"
                label="confirm new password"
                type="password"
                autocomplete="new-password"
                :error="passwordConfirmation && !passwordsMatch ? 'The passwords do not match.' : undefined"
            />

            <NoticePanel v-if="failure" tone="accent">{{ failure }}</NoticePanel>

            <button type="submit" class="btn btn-primary" :disabled="!passwordsMatch || busy">
                {{ busy ? 're-wrapping keys…' : 'set new password' }}
            </button>
        </form>

        <form v-else class="max-w-sm space-y-6" @submit.prevent="useRecoveryCode">
            <TextField v-model="email" label="email" type="email" autocomplete="username" autofocus />

            <TextField
                v-model="recoveryCode"
                label="recovery kit"
                placeholder="XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XX"
                hint="Case and dashes do not matter."
            />

            <NoticePanel v-if="failure" tone="accent">{{ failure }}</NoticePanel>

            <button type="submit" class="btn btn-primary" :disabled="!email || !recoveryCode || busy">
                {{ busy ? 'checking…' : 'continue' }}
            </button>

            <p class="text-2xs text-muted">
                <Link href="/login" class="underline underline-offset-2">back to sign in</Link>
            </p>
        </form>
    </AuthLayout>
</template>
