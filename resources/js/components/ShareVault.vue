<script setup lang="ts">
/**
 * Sharing a vault with someone, and the fingerprint check that gates it.
 *
 * The flow is deliberately interruptible in one place and only one: between
 * looking someone up and sealing a key to them, the user is shown a fingerprint
 * and asked to confirm it out of band. Everything else here is plumbing.
 *
 * **The hard stop.** When an identity's keys have changed since they were
 * verified, this refuses to continue and offers no button that says "share
 * anyway". That is not an oversight in the interface — a changed key is
 * precisely what a server substituting its own looks like, and a one-click
 * override would make the check ornamental. Re-verifying is a deliberate,
 * separate action with the consequence spelled out.
 */
import { router } from '@inertiajs/vue3';
import { computed, ref } from 'vue';

import IdentityFingerprint from '@/components/IdentityFingerprint.vue';
import NoticePanel from '@/components/NoticePanel.vue';
import TextField from '@/components/TextField.vue';
import { grantTimestamp, type GrantRole } from '@/crypto/grant';
import { vaultKeyHandle } from '@/crypto/worker/protocol';
import { fromBase64, toBase64 } from '@/lib/bytes';
import { describeError } from '@/lib/errors';
import { HttpError } from '@/lib/http';
import type { VaultRecord } from '@/lib/items';
import { checkIdentity, type IdentityCheck, type MembershipRecord, type PublicIdentity } from '@/lib/sharing';
import { uuid7 } from '@/lib/uuid';
import { usePins } from '@/stores/pins';
import { useSession } from '@/stores/session';

const props = defineProps<{
    vault: VaultRecord;
    members: MembershipRecord[];
    ownUuid: string;
}>();

const { crypto } = useSession();
const { state: pins, trust } = usePins();

const handle = ref('');
const role = ref<GrantRole>('viewer');
const candidate = ref<PublicIdentity | null>(null);
const check = ref<IdentityCheck | null>(null);
const failure = ref('');
const busy = ref(false);
const handingOverTo = ref<MembershipRecord | null>(null);
const transferFailure = ref('');

const existing = computed(() => new Set(props.members.map((membership) => membership.member.uuid)));

/**
 * Who this vault could be handed to.
 *
 * The same three conditions the server enforces, so the list never offers a
 * choice that would be refused: a live membership (which is what `members`
 * holds), not already the owner, and an accepted grant — administration is the
 * last thing to hand to somebody who has not yet confirmed your fingerprint.
 */
const successors = computed(() =>
    props.members.filter((membership) => membership.role !== 'owner' && membership.acceptedAt !== null),
);

const alreadyMember = computed(() => candidate.value !== null && existing.value.has(candidate.value.uuid));

/** Sharing is only offered once the keys have been checked and match. */
const canShare = computed(() => check.value?.status === 'verified' && !alreadyMember.value && !busy.value);

async function lookUp(): Promise<void> {
    failure.value = '';
    candidate.value = null;
    check.value = null;
    busy.value = true;

    try {
        const response = await fetch(`/users/${encodeURIComponent(handle.value)}/identity`, {
            headers: { Accept: 'application/json' },
        });

        if (!response.ok) {
            failure.value =
                response.status === 404
                    ? 'No account with that handle has published any keys.'
                    : 'That account could not be looked up.';

            return;
        }

        const identity = (await response.json()) as PublicIdentity;

        candidate.value = identity;
        check.value = checkIdentity(identity, pins.pins);
    } catch (error) {
        failure.value = describeError(error, 'That account could not be looked up.');
    } finally {
        busy.value = false;
    }
}

/**
 * Records the out-of-band comparison.
 *
 * Written to the account, not just this tab: a verification held only here would
 * mean the next device — the one that has not been shown the substituted key —
 * quietly trusting on the strength of a decision it never saw.
 */
async function confirmFingerprint(): Promise<void> {
    const identity = candidate.value;
    const verdict = check.value;

    if (!identity || !verdict) {
        return;
    }

    busy.value = true;
    failure.value = '';

    try {
        await trust(crypto(), props.ownUuid, identity.uuid, verdict.fingerprint);
        check.value = checkIdentity(identity, pins.pins);
    } catch (error) {
        failure.value =
            error instanceof HttpError
                ? (error.first('expected_version') ?? error.message)
                : describeError(error, 'That verification could not be saved.');
    } finally {
        busy.value = false;
    }
}

/**
 * Seals the Vault Key to the recipient and signs the grant that names them.
 *
 * The two are separate on purpose. The sealed box is anonymous by construction —
 * an ephemeral keypair per seal, so nothing in it identifies the sender — which
 * is a property worth having and also means the recipient has no way to tell who
 * gave them access. The signature is what supplies that, and it covers the
 * recipient's fingerprint, so it cannot be replayed against a key that was
 * substituted after the fact.
 */
async function share(): Promise<void> {
    const identity = candidate.value;
    const verdict = check.value;

    if (!identity || verdict?.status !== 'verified') {
        return;
    }

    busy.value = true;
    failure.value = '';

    let sealed: string;
    let grantSignature: string;
    let grantPayload: string;
    const membershipUuid = uuid7();

    try {
        const client = crypto();

        sealed = toBase64(
            await client.sealToPublicKey(
                vaultKeyHandle(props.vault.uuid),
                fromBase64(identity.x25519PublicKey),
                { context: 'vault.membership.key', subject: membershipUuid, version: 1 },
            ),
        );

        const signed = await client.signGrant({
            vaultUuid: props.vault.uuid,
            recipientUuid: identity.uuid,
            recipientFingerprint: verdict.fingerprint,
            role: role.value,
            keyEpoch: props.vault.keyEpoch,
            grantedAt: grantTimestamp(),
        });

        grantSignature = toBase64(signed.signature);
        grantPayload = signed.payload;
    } catch (error) {
        failure.value = describeError(error, 'The vault key could not be sealed to that account.');
        busy.value = false;

        return;
    }

    router.post(
        `/vaults/${props.vault.uuid}/memberships`,
        {
            membership_uuid: membershipUuid,
            user_uuid: identity.uuid,
            role: role.value,
            wrapped_vault_key: sealed,
            grant_signature: grantSignature,
            grant_payload: grantPayload,
        },
        {
            onSuccess: () => {
                handle.value = '';
                candidate.value = null;
                check.value = null;
            },
            onError: (errors) => {
                failure.value = Object.values(errors)[0] ?? 'That grant could not be saved.';
            },
            onFinish: () => {
                busy.value = false;
            },
        },
    );
}

function revoke(membership: MembershipRecord): void {
    router.delete(`/memberships/${membership.uuid}`);
}

/**
 * Hands the vault over.
 *
 * No crypto, and that is worth noticing rather than glossing: every other write
 * on this screen seals something first, because it changes who can decrypt.
 * This one changes who may administer, and the recipient has held a copy of the
 * Vault Key since the moment they were granted access. There is nothing to seal.
 */
function transfer(membership: MembershipRecord): void {
    transferFailure.value = '';
    handingOverTo.value = null;

    router.patch(
        `/vaults/${props.vault.uuid}/owner`,
        { user_uuid: membership.member.uuid },
        {
            onError: (errors) => {
                transferFailure.value = Object.values(errors)[0] ?? 'This vault could not be handed over.';
            },
        },
    );
}
</script>

<template>
    <section class="panel mt-8 p-4">
        <h2 class="text-2xs tracking-[0.08em] text-faint uppercase">who can read this vault</h2>

        <ul class="mt-4 divide-y divide-line">
            <li
                v-for="membership in members"
                :key="membership.uuid"
                class="flex items-baseline justify-between gap-4 py-3"
            >
                <span>
                    <span class="text-sm">{{ membership.member.displayName }}</span>
                    <span class="ml-2 text-2xs text-faint">@{{ membership.member.handle }}</span>
                    <span class="mt-1 block text-2xs text-muted">
                        {{ membership.role }}
                        <template v-if="membership.acceptedAt"> &middot; accepted</template>
                        <template v-else-if="membership.role !== 'owner'">
                            &middot; has not confirmed your fingerprint yet
                        </template>
                    </span>
                </span>

                <button
                    v-if="membership.role !== 'owner'"
                    type="button"
                    class="text-2xs text-muted hover:text-accent"
                    @click="revoke(membership)"
                >
                    revoke
                </button>
            </li>
        </ul>

        <!--
            Said plainly, because it is the one thing about revocation people
            reliably get wrong. Rotation changes what happens next; it cannot
            reach into a browser that already read something.
        -->
        <p class="mt-3 max-w-prose text-2xs text-faint">
            Revoking cuts off access immediately and prompts you to re-key the vault. It cannot retract
            anything they have already read or copied.
        </p>

        <form class="mt-8 space-y-6 border-t border-line pt-6" @submit.prevent="lookUp">
            <TextField
                v-model="handle"
                label="share with"
                hint="Their handle. You will be shown their fingerprint before anything is sent."
            />

            <div class="flex items-center gap-4">
                <label class="text-2xs text-muted" for="share-role">role</label>
                <select id="share-role" v-model="role" class="field w-auto">
                    <option value="viewer">viewer — can read</option>
                    <option value="editor">editor — can read and change</option>
                </select>

                <button type="submit" class="btn" :disabled="!handle || busy">look up</button>
            </div>
        </form>

        <NoticePanel v-if="failure" tone="accent" class="mt-6">{{ failure }}</NoticePanel>

        <div v-if="candidate && check" class="mt-6 space-y-4">
            <div class="panel p-4">
                <p class="text-sm">
                    {{ candidate.displayName }}
                    <span class="text-2xs text-faint">@{{ candidate.handle }}</span>
                </p>

                <IdentityFingerprint
                    v-if="check.fingerprint"
                    :fingerprint="check.fingerprint"
                    label="their fingerprint"
                    class="mt-4"
                />
            </div>

            <!--
                A changed key is the hard stop. No "continue anyway" button
                exists on this screen, and re-verifying is a separate action
                whose wording says what it costs.
            -->
            <NoticePanel v-if="check.status === 'changed'" tone="accent" heading="stop — these keys changed">
                <p>{{ check.detail }}</p>
                <p class="mt-3">
                    Do not continue until you have confirmed the fingerprint above with them through a channel
                    this server does not control — in person, or a call where you recognise the voice.
                </p>
                <button type="button" class="btn mt-4" :disabled="busy" @click="confirmFingerprint">
                    I checked it out of band, and it matches
                </button>
            </NoticePanel>

            <NoticePanel v-else-if="check.status === 'invalid'" tone="accent" heading="unusable keys">
                {{ check.detail }}
            </NoticePanel>

            <NoticePanel v-else-if="check.status === 'unverified'" heading="verify before sharing">
                <p>
                    You have not seen these keys before. Compare the fingerprint above with them through a
                    channel this server does not control — the picture is a quick check, the characters are
                    the real one.
                </p>
                <button type="button" class="btn mt-4" :disabled="busy" @click="confirmFingerprint">
                    it matches
                </button>
            </NoticePanel>

            <NoticePanel v-else-if="alreadyMember">
                {{ candidate.displayName }} already has access to this vault.
            </NoticePanel>

            <button v-if="canShare" type="button" class="btn btn-primary" @click="share">
                share with {{ candidate.displayName }} as {{ role }}
            </button>
        </div>

        <p v-if="pins.failure" class="mt-4 text-2xs text-accent">{{ pins.failure }}</p>

        <!--
            Handing the vault over. Shown only when there is somebody to hand it
            to, because a section offering an empty list would read as a broken
            feature rather than an inapplicable one.
        -->
        <div v-if="successors.length" class="mt-8 border-t border-line pt-6">
            <h3 class="text-2xs tracking-[0.08em] text-faint uppercase">hand this vault over</h3>

            <p class="mt-3 max-w-prose text-2xs text-muted">
                They become the owner and you become an editor. Nothing is re-encrypted, because they already
                hold the key — this changes who may share, revoke, re-key and delete. You keep your own copy
                of the key and can still read everything here; if the point is to leave, ask the new owner to
                revoke you afterwards, which prompts them to re-key.
            </p>

            <p class="mt-3 max-w-prose text-2xs text-faint">
                It also lets you delete a vault you no longer need: while anyone else has access, deleting is
                refused, since it would leave them holding a key to rows that have gone.
            </p>

            <NoticePanel v-if="transferFailure" tone="accent" class="mt-4">{{ transferFailure }}</NoticePanel>

            <ul class="mt-4 space-y-2">
                <li
                    v-for="membership in successors"
                    :key="membership.uuid"
                    class="flex items-baseline justify-between gap-4"
                >
                    <span class="text-2xs text-muted">
                        {{ membership.member.displayName }}
                        <span class="text-faint">@{{ membership.member.handle }}</span>
                    </span>
                    <button
                        type="button"
                        class="text-2xs text-muted hover:text-accent"
                        @click="handingOverTo = membership"
                    >
                        make owner
                    </button>
                </li>
            </ul>

            <NoticePanel
                v-if="handingOverTo"
                tone="accent"
                :heading="`hand this vault to ${handingOverTo.member.displayName}?`"
                class="mt-4"
            >
                <p>
                    {{ handingOverTo.member.displayName }} becomes the owner and you become an editor. They
                    will be able to revoke your access; you will not be able to revoke theirs. This cannot be
                    undone from your side.
                </p>
                <div class="mt-3 flex gap-3">
                    <button type="button" class="btn btn-primary" @click="transfer(handingOverTo)">
                        hand it over
                    </button>
                    <button type="button" class="btn" @click="handingOverTo = null">cancel</button>
                </div>
            </NoticePanel>
        </div>
    </section>
</template>
