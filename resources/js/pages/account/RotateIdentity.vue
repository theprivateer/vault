<script setup lang="ts">
/**
 * Replacing your own identity keys.
 *
 * **Everything happens in this tab, and it is self-service for a reason worth
 * understanding.** Every Vault Key you hold arrived as a sealed box addressed to
 * your X25519 public key, and you still hold the matching private key — so this
 * browser can open each one and re-seal it to a fresh pair without any vault
 * owner being involved and without a single Vault Key changing.
 *
 * **All of it goes at once.** The old private key is discarded when this lands,
 * so a membership left out of the submission is a vault you could never open
 * again — silently, with the request having said "done". The server refuses an
 * incomplete set, which is the same defence a vault re-key uses against the same
 * failure.
 *
 * The keys held by the Worker are replaced only *after* the write succeeds. A
 * rejected submission therefore changes nothing at all, rather than leaving this
 * tab holding keys the server has never seen.
 */
import { Head, Link, router } from '@inertiajs/vue3';
import { computed, ref } from 'vue';

import IdentityFingerprint from '@/components/IdentityFingerprint.vue';
import NoticePanel from '@/components/NoticePanel.vue';
import AppLayout from '@/layouts/AppLayout.vue';
import { fingerprintHex } from '@/crypto/grant';
import { computeFingerprint } from '@/crypto/identity';
import { rotationTimestamp } from '@/crypto/rotation';
import { fromBase64, toBase64 } from '@/lib/bytes';
import { describeError } from '@/lib/errors';
import { loadIdentity } from '@/lib/items';
import { useShared } from '@/lib/page';
import { useSession } from '@/stores/session';

interface RotatableMembership {
    uuid: string;
    wrappedVaultKey: string;
    vaultUuid: string;
    role: string;
}

const props = defineProps<{
    /**
     * This account's own key health.
     *
     * Shown here rather than on an operator dashboard: D11 has no organisation
     * layer, and inventing an administrator role to host one would grant a view
     * over everybody's accounts the product otherwise refuses. Each person sees
     * the part they can act on, where they can act on it.
     */
    kdf: {
        current: { m: number; t: number; p: number };
        target: { m: number; t: number; p: number };
        behind: boolean;
    };
    rotatedAt: string | null;
    identity: {
        x25519PublicKey: string;
        ed25519PublicKey: string;
        x25519PrivateKeyCt: string;
        ed25519PrivateKeyCt: string;
        fingerprint: string;
        selfSignature: string;
    } | null;
    memberships: RotatableMembership[];
}>();

const page = useShared();
const { isUnlocked, crypto } = useSession();

const confirming = ref(false);
const busy = ref(false);
const failure = ref('');

const ownUuid = computed(() => page.props.auth.user?.uuid ?? '');

/**
 * Recomputed from the keys rather than read from `identity.fingerprint`.
 *
 * The served value is the server's cache of it, and this is the number the user
 * is about to be told to read out to their colleagues. Showing a fingerprint the
 * server chose, next to keys it also chose, would be showing two of its own
 * values agreeing with each other.
 */
const currentFingerprint = computed(() => {
    const identity = props.identity;

    if (!identity) {
        return '';
    }

    return fingerprintHex(
        computeFingerprint(fromBase64(identity.ed25519PublicKey), fromBase64(identity.x25519PublicKey)),
    );
});

async function rotate(): Promise<void> {
    confirming.value = false;
    failure.value = '';
    busy.value = true;

    try {
        const client = crypto();

        const result = await client.rotateIdentity({
            uuid: ownUuid.value,
            rotatedAt: rotationTimestamp(),
            memberships: props.memberships.map((membership) => ({
                uuid: membership.uuid,
                sealed: fromBase64(membership.wrappedVaultKey),
            })),
        });

        router.post(
            '/account/identity',
            {
                x25519_public_key: toBase64(result.x25519PublicKey),
                ed25519_public_key: toBase64(result.ed25519PublicKey),
                x25519_private_key_ct: toBase64(result.x25519PrivateKeyCt),
                ed25519_private_key_ct: toBase64(result.ed25519PrivateKeyCt),
                self_signature: toBase64(result.selfSignature),
                fingerprint: toBase64(result.fingerprint),
                rotation_payload: result.certificate.payload,
                rotation_signature: toBase64(result.certificate.signature),
                memberships: result.memberships.map((membership) => ({
                    uuid: membership.uuid,
                    wrapped_vault_key: toBase64(membership.wrappedVaultKey),
                })),
            },
            {
                /*
                 | Only once the write has landed. Swapping the held keys before
                 | the server accepted would leave this tab unable to open a
                 | single membership if it refused — every sealed key on the
                 | server would still be addressed to the pair we had just
                 | thrown away.
                 */
                onSuccess: () => {
                    void loadIdentity(client, ownUuid.value, {
                        x25519PrivateKeyCt: toBase64(result.x25519PrivateKeyCt),
                        ed25519PrivateKeyCt: toBase64(result.ed25519PrivateKeyCt),
                    });
                },
                onError: (errors) => {
                    failure.value = Object.values(errors)[0] ?? 'The rotation was refused.';
                },
                onFinish: () => {
                    busy.value = false;
                },
            },
        );
    } catch (error) {
        failure.value = describeError(error, 'New keys could not be generated.');
        busy.value = false;
    }
}
</script>

<template>
    <AppLayout>
        <Head title="Identity keys" />

        <Link href="/vaults" class="text-2xs text-muted hover:text-ink">&larr; all vaults</Link>

        <h1 class="mt-4 text-base font-medium">your identity keys</h1>

        <div class="mt-4 max-w-prose space-y-3 text-sm text-muted">
            <p>
                These are the keys other people seal a vault key to when they share with you, and the keys you
                sign with. Replacing them is something you can do alone: you still hold the old private key,
                so this browser can open every vault key sealed to it and re-seal each one to the new pair.
                Nobody else has to act, and no vault key changes.
            </p>
            <p class="text-ink">
                It does not remove anyone's access to anything, and it does not help if a
                <em>vault</em> key leaked — that is a re-key, done per vault. Rotate these if the private key
                itself may have escaped: a stolen backup, a machine you no longer control.
            </p>
        </div>

        <section v-if="identity" class="panel mt-8 p-4">
            <IdentityFingerprint :fingerprint="currentFingerprint" label="your fingerprint today" />

            <p class="mt-4 max-w-prose text-2xs text-faint">
                Everyone who has verified you has this pinned. After a rotation they will see a hard stop
                instead of a green tick, and will have to check the new fingerprint with you through a channel
                this server does not control. That is deliberate.
            </p>
        </section>

        <NoticePanel v-else tone="accent" heading="no keys to replace" class="mt-8">
            This account has never published any keys, so there is nothing to rotate.
        </NoticePanel>

        <section class="panel mt-6 p-4">
            <h2 class="text-2xs tracking-[0.08em] text-faint uppercase">password stretching</h2>

            <p class="mt-3 text-2xs text-muted">
                Argon2id at {{ Math.round(kdf.current.m / 1024) }} MiB, {{ kdf.current.t }}
                {{ kdf.current.t === 1 ? 'pass' : 'passes' }}, {{ kdf.current.p }} lane<template
                    v-if="kdf.current.p !== 1"
                    >s</template
                >. This server currently asks for {{ Math.round(kdf.target.m / 1024) }} MiB,
                {{ kdf.target.t }} {{ kdf.target.t === 1 ? 'pass' : 'passes' }}.
            </p>

            <p v-if="kdf.behind" class="mt-3 max-w-prose text-2xs text-accent">
                Your account is below that, and will move up silently the next time you sign in. It cannot
                happen now: re-wrapping needs your password, and this page does not have it — the Worker keeps
                a key, never the password that produced it.
            </p>

            <p v-else class="mt-3 text-2xs text-faint">Current. Nothing to do.</p>

            <p v-if="rotatedAt" class="mt-3 text-2xs text-faint">
                These keys were last replaced on {{ new Date(rotatedAt).toLocaleDateString() }}.
            </p>
        </section>

        <NoticePanel v-if="!isUnlocked" tone="accent" class="mt-6">
            Unlock first — rotating means opening every vault key you hold.
        </NoticePanel>

        <NoticePanel v-if="failure" tone="accent" heading="nothing was changed" class="mt-6">
            {{ failure }}
        </NoticePanel>

        <section v-if="identity" class="mt-8">
            <h2 class="text-sm">what moves across</h2>

            <p class="mt-2 max-w-prose text-2xs text-muted">
                {{ memberships.length }}
                {{ memberships.length === 1 ? 'vault key' : 'vault keys' }}, re-sealed together in one
                request. A partial rotation is refused rather than half applied — the old key is discarded
                when this lands, so anything left behind could never be opened again.
            </p>

            <ul v-if="memberships.length" class="panel mt-3 divide-y divide-line">
                <li v-for="membership in memberships" :key="membership.uuid" class="p-3 text-2xs text-muted">
                    a vault you are
                    {{ membership.role === 'owner' ? 'the owner of' : `a ${membership.role} of` }}
                    <span class="ml-2 text-faint">{{ membership.vaultUuid }}</span>
                </li>
            </ul>

            <p v-else class="mt-3 text-2xs text-faint">
                You are not in any vaults, so there are no keys to carry across.
            </p>
        </section>

        <div v-if="identity" class="mt-8">
            <p v-if="busy" class="text-sm text-muted" role="status" aria-live="polite">
                generating keys and re-sealing…
            </p>

            <button
                v-else-if="!confirming"
                type="button"
                class="btn btn-primary"
                :disabled="!isUnlocked"
                @click="confirming = true"
            >
                replace my identity keys
            </button>

            <NoticePanel v-if="confirming" tone="accent" heading="replace your identity keys?">
                <p>
                    The old private key is discarded. Everyone who verified you will be shown a hard stop
                    until they check your new fingerprint out of band — including people who verified you
                    years ago and will not know why.
                </p>
                <p class="mt-3">
                    If the reason is that your old key was <em>stolen</em>, this is not enough on its own:
                    whoever has it can still read anything they already copied, and can still open any vault
                    key that was sealed to it before now. Ask each vault's owner to re-key as well.
                </p>
                <div class="mt-4 flex gap-3">
                    <button type="button" class="btn btn-primary" @click="rotate">replace them</button>
                    <button type="button" class="btn" @click="confirming = false">cancel</button>
                </div>
            </NoticePanel>
        </div>
    </AppLayout>
</template>
