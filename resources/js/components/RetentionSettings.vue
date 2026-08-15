<script setup lang="ts">
/**
 * How long this vault keeps superseded payloads.
 *
 * Two plaintext numbers, and the only settings in the application the server
 * can read — necessarily, because the server is the thing that has to enforce
 * them. A retention policy only the browser could read would be a retention
 * policy nothing applies.
 *
 * The panel states the tension rather than presenting a neutral preference.
 * Longer history recovers a value somebody overwrote by mistake; longer history
 * of a credential rotated *because it leaked* is a copy of the leaked
 * credential kept somewhere convenient. Neither direction is safe, so the
 * interface says so and lets the owner choose knowingly.
 */
import { router } from '@inertiajs/vue3';
import { computed, ref } from 'vue';

import NoticePanel from '@/components/NoticePanel.vue';
import type { VaultRecord } from '@/lib/items';

const props = defineProps<{ vault: VaultRecord }>();

const open = ref(false);
const failure = ref('');
const saved = ref(false);

/** Empty string means "follow the deployment default", which is what null posts as. */
const maxVersions = ref(props.vault.history.isDefault ? '' : String(props.vault.history.maxVersions));
const maxAgeDays = ref(props.vault.history.isDefault ? '' : String(props.vault.history.maxAgeDays));

const willErase = computed(
    () => maxVersions.value !== '' && Number(maxVersions.value) < props.vault.history.maxVersions,
);

function save(): void {
    failure.value = '';
    saved.value = false;

    router.patch(
        `/vaults/${props.vault.uuid}/history`,
        {
            max_versions: maxVersions.value === '' ? null : Number(maxVersions.value),
            max_age_days: maxAgeDays.value === '' ? null : Number(maxAgeDays.value),
        },
        {
            onSuccess: () => {
                saved.value = true;
                open.value = false;
            },
            onError: (errors) => {
                failure.value = Object.values(errors)[0] ?? 'The retention policy could not be saved.';
            },
        },
    );
}
</script>

<template>
    <section class="mt-10">
        <div class="flex items-baseline justify-between gap-4">
            <h2 class="text-sm">history retention</h2>
            <button type="button" class="text-2xs text-muted hover:text-ink" @click="open = !open">
                {{ open ? 'close' : 'change' }}
            </button>
        </div>

        <p class="mt-1 text-2xs text-muted">
            Keeping
            {{ vault.history.maxVersions }} earlier version{{ vault.history.maxVersions === 1 ? '' : 's' }} of
            each secret, for up to {{ vault.history.maxAgeDays }} days<template
                v-if="vault.history.isDefault"
            >
                — this deployment's default</template
            >.
        </p>

        <p v-if="saved" class="mt-2 text-2xs text-accent" role="status">Saved.</p>

        <div v-if="open" class="panel mt-4 space-y-6 p-4">
            <NoticePanel heading="both directions have a cost">
                History is what recovers a password somebody pasted over by mistake. It is also where a
                password you rotated <em>because it leaked</em> keeps living. Set this to zero versions for a
                vault whose contents get rotated for that reason, and use
                <span class="text-ink">erase history</span> on individual secrets for the rest.
            </NoticePanel>

            <div>
                <label class="label" for="retention-versions">versions kept</label>
                <input
                    id="retention-versions"
                    v-model="maxVersions"
                    type="number"
                    min="0"
                    max="500"
                    class="field"
                    placeholder="use the default"
                />
                <p class="mt-1 text-2xs text-muted">
                    Zero turns history off for this vault. Leave empty to follow the deployment default.
                </p>
            </div>

            <div>
                <label class="label" for="retention-days">days kept</label>
                <input
                    id="retention-days"
                    v-model="maxAgeDays"
                    type="number"
                    min="1"
                    max="3650"
                    class="field"
                    placeholder="use the default"
                />
                <p class="mt-1 text-2xs text-muted">
                    Applied overnight. Turning history off entirely is the versions field, not this one.
                </p>
            </div>

            <NoticePanel v-if="willErase" tone="accent" heading="this will delete history now">
                Lowering the count applies to what is already stored, immediately — a setting that waited
                until the next edit would tell you a number that was not true.
            </NoticePanel>

            <NoticePanel v-if="failure" tone="accent" heading="not saved">{{ failure }}</NoticePanel>

            <div class="flex gap-3">
                <button type="button" class="btn btn-primary" @click="save">save</button>
                <button type="button" class="btn" @click="open = false">cancel</button>
            </div>
        </div>
    </section>
</template>
