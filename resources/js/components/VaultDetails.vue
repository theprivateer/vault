<script setup lang="ts">
/**
 * Renaming a vault, and changing its description.
 *
 * The endpoint for this existed from Phase 3 and nothing had ever called it —
 * `PATCH /vaults/{vault}` had a route, a policy, validation and an audit action
 * whose own description reads "renamed this vault", and no interface anywhere.
 * Phase 3 task 6 asked for "create/edit forms"; secrets got the edit half and
 * the containers did not, and Phase 3 has no "carried forward" section that
 * would have caught it.
 *
 * **A rename is an ordinary re-encryption, not a metadata edit.** The name lives
 * inside `payload_ct` like everything else, so saving one generates a fresh Item
 * Key and seals the whole payload again — the same path a secret's edit takes,
 * for the same reason. There is no server-side field to update, because the
 * server has never seen a vault's name.
 *
 * Shown to anybody who may write, not only to an owner: `VaultPolicy::update` is
 * `canWrite`, so an editor who may add a lockbox may also fix a typo in the
 * vault's name. Retention and sharing sit below this and are owner-only, which
 * is a different question with a different answer.
 */
import { router } from '@inertiajs/vue3';
import { ref, watch } from 'vue';

import NoticePanel from '@/components/NoticePanel.vue';
import TextField from '@/components/TextField.vue';
import { describeError } from '@/lib/errors';
import { sealItem, type VaultPayload, type VaultRecord } from '@/lib/items';
import { useSession } from '@/stores/session';

const props = defineProps<{
    vault: VaultRecord;
    /** Null while the vault is still decrypting, or if it could not be opened. */
    payload: VaultPayload | null;
}>();

const { crypto } = useSession();

const open = ref(false);
const saving = ref(false);
const failure = ref('');
const name = ref('');
const description = ref('');

/**
 * Refilled from the payload whenever the panel is opened.
 *
 * Not initialised once at setup: the vault arrives as ciphertext and the
 * plaintext appears a moment later, so a form built at mount would open empty
 * and a save would rename the vault to nothing.
 */
watch(open, (isOpen) => {
    if (isOpen) {
        name.value = props.payload?.name ?? '';
        description.value = props.payload?.description ?? '';
        failure.value = '';
    }
});

async function save(): Promise<void> {
    failure.value = '';
    saving.value = true;

    let sealed;

    try {
        // A vault's payload is bound to the vault's own UUID, and the vault is
        // its own key context — the same subject on both sides.
        sealed = await sealItem(crypto(), props.vault.uuid, 'vault.payload', props.vault.uuid, {
            name: name.value,
            description: description.value,
        });
    } catch (error) {
        failure.value = describeError(error, 'The vault could not be encrypted.');
        saving.value = false;

        return;
    }

    // Spread rather than passed through: `SealedPayload` is an interface and
    // therefore has no implicit index signature, which is what Inertia's
    // `RequestPayload` wants. Same shape as every other write here.
    router.patch(
        `/vaults/${props.vault.uuid}`,
        { ...sealed },
        {
            preserveScroll: true,
            onSuccess: () => {
                open.value = false;
            },
            onError: (errors) => {
                failure.value = Object.values(errors)[0] ?? 'The vault could not be saved.';
            },
            onFinish: () => {
                saving.value = false;
            },
        },
    );
}
</script>

<template>
    <section class="mt-10">
        <div class="flex items-baseline justify-between gap-4">
            <h2 class="text-sm">name and description</h2>
            <button type="button" class="text-2xs text-muted hover:text-ink" @click="open = !open">
                {{ open ? 'close' : 'change' }}
            </button>
        </div>

        <p class="mt-1 text-2xs text-muted">
            Both are inside the encrypted payload, so changing either re-encrypts the vault record under a
            fresh key. Nothing else in it moves, and no secret is touched.
        </p>

        <form v-if="open" class="panel mt-4 space-y-6 p-4" @submit.prevent="save">
            <TextField v-model="name" label="name" autofocus hint="Encrypted before it leaves this page." />
            <TextField v-model="description" label="description" />

            <NoticePanel v-if="failure" tone="accent">{{ failure }}</NoticePanel>

            <button type="submit" class="btn btn-primary" :disabled="!name || saving">
                {{ saving ? 'saving…' : 'save' }}
            </button>
        </form>
    </section>
</template>
