<script setup lang="ts">
/**
 * One field of a secret, in edit mode, rendered from its schema entry.
 *
 * The whole reason lib/secretTypes.ts is a table: twelve types share this one
 * component rather than owning twelve form blocks, so adding a type is a row of
 * data and cannot introduce a new path from a decrypted value to the DOM.
 *
 * Values are shown as typed rather than masked, including the sensitive ones.
 * Editing something you cannot read is how a password gets saved with a typo in
 * it, and the masking on the row afterwards is what it is for.
 */
import { computed, ref } from 'vue';

import PasswordGenerator from '@/components/PasswordGenerator.vue';
import StrengthMeter from '@/components/StrengthMeter.vue';
import TextArea from '@/components/TextArea.vue';
import TextField from '@/components/TextField.vue';
import { parseOtpauth } from '@/crypto/totp';
import { describeError } from '@/lib/errors';
import type { SecretField } from '@/lib/secretTypes';

const props = defineProps<{
    field: SecretField;
    /** Lockboxes this vault holds, for the `lockbox` control. */
    lockboxes?: readonly { uuid: string; name: string }[];
}>();

const model = defineModel<string>({ required: true });

const showGenerator = ref(false);
const totpFailure = ref('');

const inputType = computed(() => {
    switch (props.field.control) {
        case 'url':
            return 'url';
        case 'email':
            return 'email';
        case 'number':
            return 'number';
        default:
            return 'text';
    }
});

/**
 * Accepts either a bare base32 seed or a whole `otpauth://` URI.
 *
 * Pasting the URI is what people actually have — it is what a QR code encodes,
 * and most setup pages offer it as "can't scan?" text. Parsing it here means the
 * issuer and account travel no further than this function; only the seed is
 * kept, because the rest is somebody else's label for an account we already have
 * a name for.
 *
 * **There is no camera scanner**, and that is a decision rather than an
 * omission. `Permissions-Policy` denies `camera=()` outright, lifting it would
 * weaken a header that currently denies everything, and a QR decoder is another
 * dependency for a path that ends at the same string this field accepts.
 */
function readTotp(value: string): void {
    totpFailure.value = '';

    const trimmed = value.trim();

    if (trimmed === '' || !trimmed.toLowerCase().startsWith('otpauth:')) {
        model.value = trimmed;

        return;
    }

    try {
        model.value = parseOtpauth(trimmed).secret;
    } catch (error) {
        totpFailure.value = describeError(error, 'That one-time-password URI could not be read.');
        model.value = '';
    }
}
</script>

<template>
    <div>
        <div v-if="field.control === 'lockbox'">
            <label class="label" :for="`field-${field.key}`">{{ field.label }}</label>
            <select :id="`field-${field.key}`" v-model="model" class="field">
                <option value="">none</option>
                <option v-for="box in lockboxes" :key="box.uuid" :value="box.uuid">{{ box.name }}</option>
            </select>
        </div>

        <TextArea
            v-else-if="field.control === 'textarea'"
            v-model="model"
            :label="field.label"
            :placeholder="field.placeholder"
            :hint="field.hint"
        />

        <div v-else-if="field.control === 'totp'">
            <TextField
                :model-value="model"
                :label="field.label"
                :placeholder="field.placeholder"
                :hint="field.hint"
                @update:model-value="readTotp"
            />
            <p v-if="totpFailure" class="mt-1 text-2xs text-accent">{{ totpFailure }}</p>
        </div>

        <div v-else-if="field.control === 'password'">
            <TextField v-model="model" :label="field.label" :hint="field.hint" />
            <StrengthMeter :password="model" class="mt-2" />

            <button
                type="button"
                class="mt-2 text-2xs text-muted hover:text-ink"
                :aria-expanded="showGenerator"
                @click="showGenerator = !showGenerator"
            >
                {{ showGenerator ? 'hide generator' : 'generate one' }}
            </button>

            <PasswordGenerator
                v-if="showGenerator"
                class="mt-3"
                @use="
                    (value: string) => {
                        model = value;
                        showGenerator = false;
                    }
                "
            />
        </div>

        <TextField
            v-else
            v-model="model"
            :label="field.label"
            :type="inputType"
            :placeholder="field.placeholder"
            :hint="field.hint"
        />
    </div>
</template>
