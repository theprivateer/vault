<script setup lang="ts">
/**
 * One vault: its lockboxes, and every secret in it decrypted into the store.
 *
 * The whole vault arrives as ciphertext and is opened here, rather than a page
 * at a time, because search is the client's problem (D5) and a client cannot
 * search what it has not decrypted. That is a real cost, so it is measured
 * rather than assumed — see the scale ceiling in docs/06-testing-and-ci.md —
 * and it is shown to the user as progress rather than hidden behind a spinner.
 */
import { Head, Link, router, usePage } from '@inertiajs/vue3';
import { computed, ref, watch } from 'vue';

import NoticePanel from '@/components/NoticePanel.vue';
import RetentionSettings from '@/components/RetentionSettings.vue';
import ShareVault from '@/components/ShareVault.vue';
import TextField from '@/components/TextField.vue';
import AppLayout from '@/layouts/AppLayout.vue';
import { fingerprintHex } from '@/crypto/grant';
import { computeFingerprint } from '@/crypto/identity';
import { fromBase64 } from '@/lib/bytes';
import { describeError } from '@/lib/errors';
import { sealItem, type LockboxRecord, type SecretRecord, type VaultRecord } from '@/lib/items';
import { checkMembership, type MembershipRecord } from '@/lib/sharing';
import { uuid7 } from '@/lib/uuid';
import { usePins } from '@/stores/pins';
import { useSession } from '@/stores/session';
import { useVaultContents } from '@/stores/vault';

/** The public halves of the signed-in user's own identity. */
interface OwnIdentity {
    ed25519PublicKey: string;
    x25519PublicKey: string;
}

const props = defineProps<{
    vault: VaultRecord;
    lockboxes: LockboxRecord[];
    secrets: SecretRecord[];
    members: MembershipRecord[];
    rekeyRequiredAt: string | null;
}>();

const page = usePage<{ auth: { user: { uuid: string } | null; identity: OwnIdentity | null } }>();

const { isUnlocked, crypto } = useSession();
const { state: pins } = usePins();
const { contents, busy, failure, progress, showProgress, openContents, secretsIn } = useVaultContents();

const creating = ref(false);
const name = ref('');
const description = ref('');
const createFailure = ref('');
const deleteFailure = ref('');

const canWrite = computed(() => props.vault.membership.role !== 'viewer');
const isOwner = computed(() => props.vault.membership.role === 'owner');

/**
 * Everybody else who still holds a key to this vault.
 *
 * Drives the deletion guard. The server refuses the delete either way — this is
 * a button that does not lie about what will happen, not a security control.
 */
const otherMembers = computed(() =>
    props.members.filter((membership) => membership.member.uuid !== page.props.auth.user?.uuid),
);

/**
 * This user's own fingerprint, recomputed from their own keys.
 *
 * Recomputed rather than read from `identity.fingerprint`, because that field is
 * the server's cache of it — and a grant is checked against the fingerprint it
 * names, so taking the server's word here would let a substituted key satisfy
 * its own grant.
 */
const ownFingerprint = computed(() => {
    const identity = page.props.auth.identity;

    if (!identity) {
        return '';
    }

    return fingerprintHex(
        computeFingerprint(fromBase64(identity.ed25519PublicKey), fromBase64(identity.x25519PublicKey)),
    );
});

/**
 * Whether the grant that gave *this* user access holds up.
 *
 * A membership row is something the server writes, so a vault appearing in
 * someone's list is not by itself evidence that anybody shared it with them.
 * The signature is the evidence, and until it verifies against a pinned key the
 * vault renders with a warning above it rather than as an ordinary vault.
 *
 * The owner's own membership is exempt: they created the vault, and there is
 * nobody else whose signature could be on it.
 */
const ownMembership = computed(
    () => props.members.find((membership) => membership.uuid === props.vault.membership.uuid) ?? null,
);

const trust = computed(() => {
    const membership = ownMembership.value;

    if (isOwner.value || membership === null || !ownFingerprint.value) {
        return null;
    }

    return checkMembership(membership, ownFingerprint.value, props.vault.uuid, pins.pins);
});

const unverifiedGrant = computed(() => (trust.value?.trusted === false ? trust.value : null));

function acceptGrant(): void {
    const membership = ownMembership.value;

    if (membership) {
        router.patch(`/memberships/${membership.uuid}`, {}, { preserveScroll: true });
    }
}

const openedLockboxes = computed(() => contents.value.lockboxes);
const percent = computed(() =>
    progress.value.total === 0 ? 0 : Math.round((progress.value.done / progress.value.total) * 100),
);

/**
 * Re-runs whenever the ciphertext changes or the vault is unlocked, because
 * both are reasons the plaintext on screen is no longer correct. The store
 * re-decrypts only the records whose ciphertext actually moved.
 */
watch(
    [() => props.vault, () => props.lockboxes, () => props.secrets, isUnlocked],
    async () => {
        if (!isUnlocked.value) {
            return;
        }

        await openContents(crypto(), {
            vault: props.vault,
            lockboxes: props.lockboxes,
            secrets: props.secrets,
        });
    },
    { immediate: true },
);

async function create(): Promise<void> {
    createFailure.value = '';

    let sealed;
    const uuid = uuid7();

    try {
        sealed = await sealItem(crypto(), props.vault.uuid, 'lockbox.payload', uuid, {
            name: name.value,
            description: description.value,
        });
    } catch (error) {
        createFailure.value = describeError(error, 'The lockbox could not be encrypted.');

        return;
    }

    router.post(
        `/vaults/${props.vault.uuid}/lockboxes`,
        { uuid, ...sealed, sort_order: props.lockboxes.length },
        {
            onSuccess: () => {
                name.value = '';
                description.value = '';
                creating.value = false;
            },
            onError: (errors) => {
                createFailure.value = Object.values(errors)[0] ?? 'The lockbox could not be saved.';
            },
        },
    );
}

function destroy(): void {
    deleteFailure.value = '';

    router.delete(`/vaults/${props.vault.uuid}`, {
        onError: (errors) => {
            deleteFailure.value = Object.values(errors)[0] ?? 'This vault could not be deleted.';
        },
    });
}
</script>

<template>
    <AppLayout>
        <Head :title="contents.vault?.payload?.name ?? 'Vault'" />

        <div class="flex items-baseline justify-between gap-4">
            <Link href="/vaults" class="text-2xs text-muted hover:text-ink">&larr; all vaults</Link>

            <!--
                Reachable from the vault itself rather than buried in settings.
                The log is only useful if somebody looks at it, and the moment
                they will want to is while they are standing in the vault
                wondering whether something moved.
            -->
            <Link :href="`/vaults/${props.vault.uuid}/activity`" class="text-2xs text-muted hover:text-ink">
                activity &rarr;
            </Link>
        </div>

        <!--
            A membership row is written by the server, so a vault appearing in
            your list is not evidence anyone shared it with you. The signature
            is. Until it verifies, this renders as a warning above the vault
            rather than as an ordinary vault.
        -->
        <NoticePanel
            v-if="unverifiedGrant"
            tone="accent"
            heading="this share cannot be verified"
            class="mt-4"
        >
            <p>{{ unverifiedGrant.detail }}</p>
            <p class="mt-3">
                You can still read what is here — you hold the key — but nothing shows who gave it to you.
                Confirm with them directly before trusting anything in it.
            </p>
        </NoticePanel>

        <NoticePanel
            v-else-if="trust?.trusted && !ownMembership?.acceptedAt"
            heading="verified share"
            class="mt-4"
        >
            <p>Signed by {{ ownMembership?.grantedBy?.displayName }}, whose keys you have verified.</p>
            <button type="button" class="btn mt-4" @click="acceptGrant">acknowledge</button>
        </NoticePanel>

        <!--
            Only an owner is prompted: rotating means unwrapping every item key,
            and re-sealing the new one to each remaining member.
        -->
        <NoticePanel
            v-if="rekeyRequiredAt && isOwner"
            tone="accent"
            heading="this vault needs a new key"
            class="mt-4"
        >
            <p>
                Someone was removed. Until you rotate the key, anything written from now on is still encrypted
                under a key they may have cached.
            </p>
            <Link :href="`/vaults/${props.vault.uuid}/rekey`" class="btn mt-4 inline-block">
                re-key this vault
            </Link>
        </NoticePanel>

        <NoticePanel v-if="failure" tone="accent" heading="this vault could not be opened" class="mt-4">
            {{ failure }}
        </NoticePanel>

        <div v-else class="mt-4 flex items-baseline justify-between gap-4">
            <div>
                <h1 class="text-base font-medium">{{ contents.vault?.payload?.name ?? '—' }}</h1>
                <p v-if="contents.vault?.payload?.description" class="mt-1 text-sm text-muted">
                    {{ contents.vault.payload.description }}
                </p>
                <p class="mt-1 text-2xs text-faint">
                    {{ contents.secrets.length }}
                    {{ contents.secrets.length === 1 ? 'secret' : 'secrets' }} decrypted in this browser
                    &middot; press <kbd class="text-ink">/</kbd> to search without touching the network
                </p>
            </div>

            <div class="flex items-center gap-4">
                <button v-if="canWrite" type="button" class="btn" @click="creating = !creating">
                    {{ creating ? 'cancel' : 'new lockbox' }}
                </button>
                <!--
                    Absent rather than disabled when other people hold a key.
                    A greyed-out control invites hunting for the state that
                    re-enables it; the panel below says what that state is.
                -->
                <button
                    v-if="isOwner && !otherMembers.length"
                    type="button"
                    class="text-2xs text-muted hover:text-accent"
                    @click="destroy"
                >
                    delete vault
                </button>
            </div>
        </div>

        <form v-if="creating" class="panel mt-6 space-y-6 p-4" @submit.prevent="create">
            <TextField v-model="name" label="name" autofocus hint="Encrypted before it leaves this page." />
            <TextField v-model="description" label="description" />

            <NoticePanel v-if="createFailure" tone="accent">{{ createFailure }}</NoticePanel>

            <button type="submit" class="btn btn-primary" :disabled="!name">create lockbox</button>
        </form>

        <!--
            Progress rather than a spinner. Decrypting a large vault takes real
            time, and a number that moves is the difference between "working"
            and "broken" — the one thing a spinner cannot tell you.
        -->
        <div
            v-if="showProgress"
            class="mt-6"
            role="status"
            aria-live="polite"
            :aria-label="`Decrypting ${progress.done} of ${progress.total} items`"
        >
            <p class="text-sm text-muted">decrypting {{ progress.done }} / {{ progress.total }}…</p>
            <div class="mt-2 h-px w-full bg-line">
                <div class="h-px bg-accent" :style="{ width: `${percent}%` }" />
            </div>
        </div>

        <div v-else-if="openedLockboxes.length" class="panel mt-6 divide-y divide-line">
            <div v-for="entry in openedLockboxes" :key="entry.record.uuid" class="p-4">
                <NoticePanel v-if="entry.error" tone="accent" heading="integrity failure">
                    {{ entry.error }}
                </NoticePanel>

                <Link v-else :href="`/lockboxes/${entry.record.uuid}`" class="flex justify-between gap-4">
                    <span>
                        <span class="text-sm">{{ entry.payload?.name }}</span>
                        <span v-if="entry.payload?.description" class="mt-1 block text-2xs text-muted">
                            {{ entry.payload.description }}
                        </span>
                    </span>
                    <span class="text-2xs text-faint">
                        {{ secretsIn(entry.record.uuid).length }}
                        {{ secretsIn(entry.record.uuid).length === 1 ? 'secret' : 'secrets' }}
                    </span>
                </Link>
            </div>
        </div>

        <p v-else-if="!failure && !busy" class="mt-6 text-sm text-muted">No lockboxes in this vault yet.</p>

        <NoticePanel v-if="deleteFailure" tone="accent" heading="not deleted" class="mt-6">
            {{ deleteFailure }}
        </NoticePanel>

        <RetentionSettings v-if="isOwner" :vault="props.vault" />

        <ShareVault
            v-if="isOwner && page.props.auth.user"
            :vault="props.vault"
            :members="members"
            :own-uuid="page.props.auth.user.uuid"
        />
    </AppLayout>
</template>
