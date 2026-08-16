<script setup lang="ts">
import { router } from '@inertiajs/vue3';
import { computed, onMounted, ref } from 'vue';

import NoticePanel from '@/components/NoticePanel.vue';
import RecoveryKit from '@/components/RecoveryKit.vue';
import TextField from '@/components/TextField.vue';
import type { KdfParams } from '@/crypto/primitives';
import AuthLayout from '@/layouts/AuthLayout.vue';
import { toBase64 } from '@/lib/bytes';
import { describeError } from '@/lib/errors';
import { HttpError, postJson } from '@/lib/http';
import { uuid7 } from '@/lib/uuid';
import { checkCryptoWorker, markAuthenticated, useSession } from '@/stores/session';
import { useDocumentTitle } from '@/lib/title';

const props = defineProps<{
    token: string;
    email: string;
    kdfParams: KdfParams;
}>();

type Step = 'details' | 'deriving' | 'kit';

const step = ref<Step>('details');
const recoveryCode = ref('');
const failure = ref('');

const displayName = ref('');
const handle = ref('');
const password = ref('');
const passwordConfirmation = ref('');

const { crypto: cryptoClient } = useSession();

const errors = ref<Record<string, string[]>>({});

/**
 * Set when the Worker cannot start at all.
 *
 * Checked on mount rather than on submit: there is no point letting someone
 * choose a master password, read the warning about there being no reset, and
 * commit to it, only to be told afterwards that nothing could have been
 * encrypted anyway.
 */
const unavailable = ref('');

onMounted(async () => {
    unavailable.value = (await checkCryptoWorker()) ?? '';
});

const error = (field: string): string | undefined => errors.value[field]?.[0];

const passwordsMatch = computed(
    () => password.value.length > 0 && password.value === passwordConfirmation.value,
);

const ready = computed(
    () => displayName.value.trim() !== '' && handle.value.trim() !== '' && passwordsMatch.value,
);

/**
 * Every key is generated in the Worker. What comes back is the ciphertext the
 * server will store, plus the recovery code — which has to surface, because the
 * user must write it down.
 */
async function submit(): Promise<void> {
    failure.value = '';
    step.value = 'deriving';

    const uuid = uuid7();
    const kdfSalt = crypto.getRandomValues(new Uint8Array(16));

    /*
     | Two phases, reported separately. They fail for entirely different reasons
     | — a blocked Worker versus a rejected request — and a single catch around
     | both produced a message that named the wrong one for as long as it
     | existed.
     */
    let account;

    try {
        account = await cryptoClient().register({
            password: password.value,
            kdfSalt,
            kdfParams: props.kdfParams,
            uuid,
        });
    } catch (cause) {
        failure.value = describeError(cause, 'Your keys could not be generated.');
        step.value = 'details';

        return;
    }

    try {
        await postJson(`/register/${props.token}`, {
            uuid,
            display_name: displayName.value,
            handle: handle.value,
            kdf_salt: toBase64(kdfSalt),
            kdf_params: props.kdfParams,
            auth_key: toBase64(account.authKey),
            wrapped_user_key: toBase64(account.wrappedUserKey),
            recovery_salt: toBase64(account.recoverySalt),
            recovery_wrapped_user_key: toBase64(account.recoveryWrappedUserKey),
            recovery_auth_key: toBase64(account.recoveryAuthKey),
            x25519_public_key: toBase64(account.x25519PublicKey),
            ed25519_public_key: toBase64(account.ed25519PublicKey),
            x25519_private_key_ct: toBase64(account.x25519PrivateKeyCt),
            ed25519_private_key_ct: toBase64(account.ed25519PrivateKeyCt),
            self_signature: toBase64(account.selfSignature),
            fingerprint: toBase64(account.fingerprint),
        });

        markAuthenticated();

        // Held only in this component, only until acknowledged. The server has
        // never seen it and cannot show it again.
        recoveryCode.value = account.recoveryCode;
        step.value = 'kit';
    } catch (cause) {
        if (cause instanceof HttpError) {
            errors.value = cause.errors;
            failure.value = cause.status === 422 ? '' : cause.message;
        } else {
            failure.value = describeError(cause, 'Your account could not be created.');
        }

        step.value = 'details';
    }
}

useDocumentTitle('Create your account');
</script>

<template>
    <AuthLayout
        :title="step === 'kit' ? 'Save your recovery kit' : 'Create your account'"
        :subtitle="
            step === 'kit'
                ? undefined
                : 'Your keys are generated here, in this browser. Your password never leaves it.'
        "
        :step="step === 'kit' ? 'step 2 of 2' : 'step 1 of 2'"
    >
        <RecoveryKit
            v-if="step === 'kit'"
            :code="recoveryCode"
            :email="email"
            @acknowledged="router.visit('/vaults')"
        />

        <form v-else class="space-y-6" @submit.prevent="submit">
            <NoticePanel v-if="unavailable" tone="accent" heading="encryption unavailable">
                {{ unavailable }}
            </NoticePanel>

            <div>
                <p class="label">invited address</p>
                <p class="text-sm">{{ email }}</p>
            </div>

            <TextField
                v-model="displayName"
                label="display name"
                autocomplete="name"
                :error="error('display_name')"
                autofocus
            />

            <TextField
                v-model="handle"
                label="handle"
                hint="How others find you when sharing a vault. Lowercase letters, numbers, dots and dashes."
                autocomplete="username"
                :error="error('handle')"
            />

            <TextField
                v-model="password"
                label="master password"
                type="password"
                autocomplete="new-password"
                hint="Long and memorable beats short and complicated. This is the only thing protecting your vault."
            />

            <TextField
                v-model="passwordConfirmation"
                label="confirm master password"
                type="password"
                autocomplete="new-password"
                :error="passwordConfirmation && !passwordsMatch ? 'The passwords do not match.' : undefined"
            />

            <NoticePanel v-if="failure || error('uuid')" tone="accent">
                {{ failure || 'Something went wrong. Please try again.' }}
            </NoticePanel>

            <NoticePanel heading="there is no password reset">
                Nobody can reset this password for you, because nobody else can decrypt your vault. You will
                be given a recovery kit on the next screen — that is the only way back in.
            </NoticePanel>

            <button
                type="submit"
                class="btn btn-primary"
                :disabled="!ready || step === 'deriving' || unavailable !== ''"
            >
                {{ step === 'deriving' ? 'generating keys…' : 'create account' }}
            </button>

            <p v-if="step === 'deriving'" class="text-2xs text-muted">
                Stretching your password. This is deliberately slow — it is what makes a stolen database
                expensive to attack.
            </p>
        </form>
    </AuthLayout>
</template>
