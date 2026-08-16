<script setup lang="ts">
/**
 * Rotating a vault's key after someone was removed.
 *
 * Everything happens in this tab: a new Vault Key is generated, every item key
 * is unwrapped under the old one and re-wrapped under the new one, the new key
 * is sealed to each remaining member, and the whole set is submitted as a single
 * request. The server takes it only at exactly `key_epoch + 1` and only if the
 * set is complete, so there is no half-rotated state to land in — which is the
 * failure the 2017 `vault:key` command shipped with.
 *
 * **Every remaining member's fingerprint is checked first.** Rotation seals a
 * fresh key to each of them, so a member whose public key was substituted since
 * the last check would be handed the new key by this very operation. Verifying
 * before re-keying is not belt and braces; without it, rotation is a delivery
 * mechanism.
 */
import { Head, Link, router } from '@inertiajs/vue3';
import { computed, ref } from 'vue';

import IdentityFingerprint from '@/components/IdentityFingerprint.vue';
import NoticePanel from '@/components/NoticePanel.vue';
import AppLayout from '@/layouts/AppLayout.vue';
import { itemKeyHandle, vaultKeyHandle } from '@/crypto/worker/protocol';
import { fromBase64, toBase64 } from '@/lib/bytes';
import { describeError } from '@/lib/errors';
import type { VaultRecord } from '@/lib/items';
import { checkIdentity, type MembershipRecord, type PublicIdentity } from '@/lib/sharing';
import { useShared } from '@/lib/page';
import { usePins } from '@/stores/pins';
import { useSession } from '@/stores/session';

interface RekeyItem {
    uuid: string;
    wrappedItemKey: string;
}

interface RekeyMember extends MembershipRecord {
    identity: PublicIdentity | null;
}

const props = defineProps<{
    vault: VaultRecord;
    items: RekeyItem[];
    members: RekeyMember[];
    /** Whether a revocation demanded this, as against somebody choosing it. */
    required: boolean;
}>();

const page = useShared();
const { isUnlocked, crypto } = useSession();
const { state: pins, trust } = usePins();

/*
 | The signed-in user's own identifier, which is what the pin store is bound to.
 | Not the membership uuid: pins belong to a person, not to one vault's row for
 | them, and sealing them under the wrong subject would make the store
 | unreadable on the next page that asked for it.
 */
const ownUuid = computed(() => page.props.auth.user?.uuid ?? '');

const failure = ref('');
const busy = ref(false);
const done = ref(0);

/*
 | Empty string means "follow the deployment default", which is a different
 | answer from 0 ("never remind me"). The field starts blank when this vault has
 | no opinion of its own so that saving without touching it keeps it that way.
 */
const afterDays = ref(props.vault.rotation.isDefault ? '' : String(props.vault.rotation.afterDays));
const savingSchedule = ref(false);
const scheduleFailure = ref('');

function saveSchedule(): void {
    savingSchedule.value = true;
    scheduleFailure.value = '';

    router.patch(
        `/vaults/${props.vault.uuid}/rekey/schedule`,
        { after_days: afterDays.value === '' ? null : Number(afterDays.value) },
        {
            preserveScroll: true,
            onError: (errors) => {
                scheduleFailure.value = Object.values(errors)[0] ?? 'That could not be saved.';
            },
            onFinish: () => {
                savingSchedule.value = false;
            },
        },
    );
}

/** One check per member, recomputed whenever a pin is added. */
const checks = computed(() =>
    props.members.map((member) => ({
        member,
        check: member.identity === null ? null : checkIdentity(member.identity, pins.pins),
    })),
);

const unverified = computed(() =>
    checks.value.filter(({ check }) => check === null || check.status !== 'verified'),
);

const ready = computed(() => isUnlocked.value && unverified.value.length === 0 && !busy.value);

async function verify(member: RekeyMember, fingerprint: string): Promise<void> {
    if (member.identity === null) {
        return;
    }

    busy.value = true;
    failure.value = '';

    try {
        await trust(crypto(), ownUuid.value, member.identity.uuid, fingerprint);
    } catch (error) {
        failure.value = describeError(error, 'That verification could not be saved.');
    } finally {
        busy.value = false;
    }
}

/**
 * Builds the whole rotation, then submits it once.
 *
 * The old Vault Key stays under its handle throughout, because every unwrap
 * needs it; the new one is generated under a temporary handle and only becomes
 * the vault's key once the server has accepted the write. Doing it the other way
 * round would leave this tab holding a key the server never took, unable to read
 * the vault it is looking at.
 */
async function rekey(): Promise<void> {
    busy.value = true;
    failure.value = '';
    done.value = 0;

    const oldKey = vaultKeyHandle(props.vault.uuid);
    const newKey = `${oldKey}:next`;
    const client = crypto();

    try {
        await client.generateInto(newKey);

        const items: Array<{ uuid: string; wrapped_item_key: string }> = [];

        for (const item of props.items) {
            const scratch = itemKeyHandle(item.uuid);

            await client.unwrapInto({
                handle: scratch,
                using: oldKey,
                wrapped: fromBase64(item.wrappedItemKey),
                aad: { context: 'item.key', subject: item.uuid, version: 1 },
            });

            items.push({
                uuid: item.uuid,
                wrapped_item_key: toBase64(
                    await client.wrapFrom(scratch, newKey, {
                        context: 'item.key',
                        subject: item.uuid,
                        version: 1,
                    }),
                ),
            });

            await client.forget(scratch);
            done.value++;
        }

        // The vault's own payload key, which lives on the vault row rather than
        // in the item set.
        const vaultItemKey = itemKeyHandle(props.vault.uuid);

        await client.unwrapInto({
            handle: vaultItemKey,
            using: oldKey,
            wrapped: fromBase64(props.vault.wrappedItemKey),
            aad: { context: 'item.key', subject: props.vault.uuid, version: 1 },
        });

        const vaultWrapped = toBase64(
            await client.wrapFrom(vaultItemKey, newKey, {
                context: 'item.key',
                subject: props.vault.uuid,
                version: 1,
            }),
        );

        await client.forget(vaultItemKey);

        const memberships = [];

        for (const { member, check } of checks.value) {
            if (member.identity === null || check?.status !== 'verified') {
                throw new Error('A member’s keys are not verified. Nothing was sent.');
            }

            memberships.push({
                uuid: member.uuid,
                wrapped_vault_key: toBase64(
                    await client.sealToPublicKey(newKey, fromBase64(member.identity.x25519PublicKey), {
                        context: 'vault.membership.key',
                        subject: member.uuid,
                        version: 1,
                    }),
                ),
            });
        }

        router.post(
            `/vaults/${props.vault.uuid}/rekey`,
            {
                key_epoch: props.vault.keyEpoch + 1,
                vault_wrapped_item_key: vaultWrapped,
                items,
                memberships,
            },
            {
                onError: (errors) => {
                    failure.value = Object.values(errors)[0] ?? 'The re-key was refused.';
                },
                onFinish: () => {
                    busy.value = false;
                    // Dropped either way: if the write failed the vault is
                    // still on its old key, and this one opens nothing.
                    void client.forget(newKey);
                },
            },
        );
    } catch (error) {
        failure.value = describeError(error, 'The vault key could not be rotated.');
        busy.value = false;
        void client.forget(newKey);
    }
}
</script>

<template>
    <AppLayout>
        <Head title="Re-key vault" />

        <Link :href="`/vaults/${vault.uuid}`" class="text-2xs text-muted hover:text-ink">
            &larr; back to vault
        </Link>

        <h1 class="mt-4 text-base font-medium">Re-key this vault</h1>

        <div class="mt-4 max-w-prose space-y-3 text-sm text-muted">
            <!--
                Two reasons to be on this page, and they deserve different
                sentences. One is a consequence of a revocation; the other is
                somebody choosing to rotate. Telling a person who came here
                deliberately that "someone was removed" would be describing an
                event that did not happen.
            -->
            <p v-if="required">
                Someone was removed from this vault. Rotating the key means everything written from now on is
                encrypted under a key they do not have.
            </p>
            <p v-else>
                Rotating replaces this vault's key. Everything written from now on is encrypted under the new
                one, and anyone holding a copy of the old key — a lost laptop, a browser you no longer trust —
                stops being able to read what comes next.
            </p>
            <!--
                The limit, stated where the action is taken rather than buried
                in documentation. It is the thing people assume rotation does.
            -->
            <p class="text-ink">
                It cannot retract what they already read. Anything they opened or copied before now is theirs,
                and no key change reaches into a browser after the fact. Treat those secrets as known and
                rotate the credentials themselves.
            </p>
            <p>
                {{ items.length }} item {{ items.length === 1 ? 'key' : 'keys' }} and {{ members.length }}
                {{ members.length === 1 ? 'member' : 'members' }} are re-wrapped together, in one request. A
                partial re-key is refused rather than half applied.
            </p>
        </div>

        <NoticePanel v-if="!isUnlocked" tone="accent" class="mt-6">
            Unlock the vault first — rotating the key means reading every existing one.
        </NoticePanel>

        <section class="panel mt-6 p-4">
            <h2 class="text-2xs tracking-[0.08em] text-faint uppercase">confirm who gets the new key</h2>

            <p class="mt-2 max-w-prose text-2xs text-muted">
                Each of these people will be sent the new key. Check their fingerprints now: if one of them
                was substituted since you last looked, this is the step that would hand the new key to whoever
                did it.
            </p>

            <ul class="mt-4 divide-y divide-line">
                <li v-for="{ member, check } in checks" :key="member.uuid" class="py-4">
                    <div class="flex items-baseline justify-between gap-4">
                        <span>
                            <span class="text-sm">{{ member.member.displayName }}</span>
                            <span class="ml-2 text-2xs text-faint">@{{ member.member.handle }}</span>
                        </span>
                        <span class="text-2xs text-muted">{{ member.role }}</span>
                    </div>

                    <IdentityFingerprint
                        v-if="check?.fingerprint"
                        :fingerprint="check.fingerprint"
                        class="mt-3"
                    />

                    <NoticePanel v-if="check === null" tone="accent" heading="no published keys" class="mt-3">
                        This account has no keys to seal a vault key to. Remove them before re-keying.
                    </NoticePanel>

                    <NoticePanel
                        v-else-if="check.status === 'changed'"
                        tone="accent"
                        heading="stop — these keys changed"
                        class="mt-3"
                    >
                        <p>{{ check.detail }}</p>
                        <button
                            type="button"
                            class="btn mt-4"
                            :disabled="busy"
                            @click="verify(member, check.fingerprint)"
                        >
                            I checked it out of band, and it matches
                        </button>
                    </NoticePanel>

                    <NoticePanel
                        v-else-if="check.status === 'invalid'"
                        tone="accent"
                        heading="unusable keys"
                        class="mt-3"
                    >
                        {{ check.detail }}
                    </NoticePanel>

                    <div v-else-if="check.status === 'unverified'" class="mt-3">
                        <button
                            type="button"
                            class="btn"
                            :disabled="busy"
                            @click="verify(member, check.fingerprint)"
                        >
                            it matches
                        </button>
                    </div>

                    <p v-else class="mt-2 text-2xs text-muted">verified</p>
                </li>
            </ul>
        </section>

        <NoticePanel v-if="failure" tone="accent" class="mt-6" heading="nothing was changed">
            {{ failure }}
        </NoticePanel>

        <div v-if="busy" class="mt-6 text-sm text-muted" role="status" aria-live="polite">
            re-wrapping {{ done }} / {{ items.length }}…
        </div>

        <button type="button" class="btn btn-primary mt-6" :disabled="!ready" @click="rekey">
            rotate the vault key
        </button>

        <p v-if="unverified.length" class="mt-3 text-2xs text-faint">
            {{ unverified.length }}
            {{ unverified.length === 1 ? 'member still needs' : 'members still need' }} checking before this
            can run.
        </p>

        <!--
            The other maintenance operation on this vault's cryptography, linked
            from here so the two live together — and separated in words, because
            they are easy to confuse and fix different things. A re-key changes
            which key opens the vault; a re-seal changes the envelope around
            payloads that key already opens.
        -->
        <section class="panel mt-10 p-4">
            <h2 class="text-2xs tracking-[0.08em] text-faint uppercase">envelope versions</h2>

            <p class="mt-2 max-w-prose text-2xs text-muted">
                Rotating re-wraps every key in this vault, which brings the wrapped keys onto the current
                envelope version as a side effect. It does not touch the payloads — those are re-sealed only
                when something writes them, so anything nobody has edited stays where it is.
            </p>

            <Link :href="`/vaults/${vault.uuid}/reseal`" class="btn mt-4 inline-block">
                re-seal this vault's payloads
            </Link>
        </section>

        <!--
            A reminder, and the page is careful to say that is all it is. There
            is no job behind this number and there cannot be: rotating needs a
            browser holding the current Vault Key, which no server ever does.
        -->
        <section class="panel mt-10 p-4">
            <h2 class="text-2xs tracking-[0.08em] text-faint uppercase">remind me to rotate</h2>

            <p class="mt-2 max-w-prose text-2xs text-muted">
                This key was last changed
                <template v-if="vault.rotation.rotatedAt">
                    on {{ new Date(vault.rotation.rotatedAt).toLocaleDateString() }}</template
                ><template v-else> at some point before this was recorded</template>. Nothing rotates on a
                timer — the server cannot, since only a member can unwrap the current key — so this only
                decides when the vault page starts saying the key is old.
            </p>

            <p class="mt-2 max-w-prose text-2xs text-faint">
                Worth knowing what an interval buys: rotation leaves every payload ciphertext untouched, so it
                does not re-protect anything already written. It bounds how long a key that escaped keeps
                opening what comes next. Useful when you think one did; close to ritual otherwise.
            </p>

            <form class="mt-4 flex items-end gap-3" @submit.prevent="saveSchedule">
                <label class="text-2xs text-muted">
                    <span class="block">every … days (0 for never, blank for the default)</span>
                    <input
                        v-model="afterDays"
                        type="number"
                        min="0"
                        max="3650"
                        class="field mt-1 w-40"
                        :placeholder="String(vault.rotation.afterDays)"
                    />
                </label>
                <button type="submit" class="btn" :disabled="savingSchedule">save</button>
            </form>

            <p v-if="scheduleFailure" class="mt-3 text-2xs text-accent">{{ scheduleFailure }}</p>
        </section>
    </AppLayout>
</template>
