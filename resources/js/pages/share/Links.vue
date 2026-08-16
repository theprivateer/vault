<script setup lang="ts">
/**
 * Links you have issued, and links you can withdraw.
 *
 * A share link is a credential sitting in somebody else's inbox, and until this
 * page existed the only way to take one back was to reach the endpoint by hand.
 * That is the gap this closes: the list is derived from exactly the same rule as
 * the revoke ability — your own links, plus any issued into a vault you
 * administer — so there is no power here that cannot be found.
 *
 * **The names are decrypted in this tab.** The server can say a link exists,
 * when it expires and how often it has been opened; what it points at is inside
 * `payload_ct`. So the page unwraps each relevant Vault Key and opens each
 * secret's payload, and where it cannot — a link into a vault you have since
 * been removed from, or one whose secret has been deleted — it says so rather
 * than showing a blank row.
 *
 * The vault store is deliberately untouched. It holds one vault at a time and
 * wipes when you move between them; this page spans vaults, and routing it
 * through the store would empty whatever the user had open.
 */
import { Link, router } from '@inertiajs/vue3';
import { computed, ref, watch } from 'vue';

import NoticePanel from '@/components/NoticePanel.vue';
import AppLayout from '@/layouts/AppLayout.vue';
import { openAll, useDecryption } from '@/lib/decrypt';
import { openVaultKey } from '@/lib/items';
import type { SecretPayload, SecretRecord, VaultRecord } from '@/lib/items';
import type { ShareLinkRecord } from '@/lib/sharelink';
import { useSession } from '@/stores/session';
import { useDocumentTitle } from '@/lib/title';

const props = defineProps<{
    links: ShareLinkRecord[];
    secrets: SecretRecord[];
    vaults: VaultRecord[];
}>();

const { isUnlocked, crypto } = useSession();
const { busy, failure, run } = useDecryption();

/** Secret UUID to its decrypted name, for the rows this tab could open. */
const names = ref(new Map<string, string>());
const writeFailure = ref('');
const confirming = ref<string | null>(null);

const outstanding = computed(() => props.links.filter((link) => link.redeemable));
const finished = computed(() => props.links.filter((link) => !link.redeemable));

watch(
    [() => props.links, isUnlocked],
    () => {
        if (isUnlocked.value) {
            void load();
        }
    },
    { immediate: true },
);

/**
 * Opens each vault key, then the secrets under it.
 *
 * Grouped by vault because a Vault Key has to be unwrapped before anything it
 * protects, and doing that once per vault rather than once per link is the
 * difference between one unwrap and twenty.
 */
async function load(): Promise<void> {
    await run(async () => {
        const client = crypto();
        const found = new Map<string, string>();

        for (const vault of props.vaults) {
            try {
                // Only the key. This page never shows a vault's own name, and
                // decrypting a payload it will not render would be work done to
                // be thrown away.
                await openVaultKey(client, vault);
            } catch {
                // One unreadable vault must not stop the others being named.
                continue;
            }

            const mine = props.secrets.filter((secret) =>
                props.links.some((link) => link.secretUuid === secret.uuid && link.vaultUuid === vault.uuid),
            );

            const secrets = await openAll<SecretRecord, SecretPayload>(
                client,
                vault.uuid,
                'secret.payload',
                mine,
                () => 'This secret',
            );

            for (const entry of secrets) {
                if (entry.payload) {
                    found.set(entry.record.uuid, entry.payload.key);
                }
            }
        }

        names.value = found;
    });
}

/**
 * What to call a link's target.
 *
 * Three genuinely different situations, and collapsing them would leave someone
 * unable to tell "I cannot read this" from "there is nothing to read".
 */
function describes(link: ShareLinkRecord): string {
    if (link.secretUuid === null) {
        return 'a secret that has since been deleted';
    }

    return names.value.get(link.secretUuid) ?? 'a secret in a vault you can no longer open';
}

function status(link: ShareLinkRecord): string {
    if (link.revokedAt !== null) {
        return 'withdrawn';
    }

    if (new Date(link.expiresAt) <= new Date()) {
        return 'expired';
    }

    if (link.viewCount >= link.maxViews) {
        return 'used up';
    }

    return `${link.maxViews - link.viewCount} of ${link.maxViews} opens left`;
}

function when(iso: string): string {
    return new Date(iso).toLocaleString();
}

function revoke(uuid: string): void {
    writeFailure.value = '';
    confirming.value = null;

    router.delete(`/links/${uuid}`, {
        onError: (errors) => {
            writeFailure.value = Object.values(errors)[0] ?? 'The link could not be withdrawn.';
        },
    });
}

useDocumentTitle('Your links');
</script>

<template>
    <AppLayout>
        <h1 class="text-base font-medium">your links</h1>

        <NoticePanel heading="a link is a credential, wherever you sent it" class="mt-4">
            Withdrawing one stops it opening from this moment on. It cannot reach into the chat window or
            inbox you sent it to, and it cannot un-read anything already read — if a link has been opened,
            treat what it carried as known and rotate it.
        </NoticePanel>

        <NoticePanel v-if="failure" tone="accent" heading="some names could not be read" class="mt-4">
            {{ failure }}
        </NoticePanel>

        <NoticePanel v-if="writeFailure" tone="accent" heading="not withdrawn" class="mt-4">
            {{ writeFailure }}
        </NoticePanel>

        <p v-if="busy" class="mt-6 text-sm text-muted" role="status">decrypting…</p>

        <p v-else-if="!links.length" class="mt-6 text-sm text-muted">
            You have no outstanding links. Ones that expire or get used up are swept away within the hour.
        </p>

        <template v-else>
            <section v-if="outstanding.length" class="mt-8">
                <h2 class="text-sm">still open</h2>

                <div class="panel mt-2 divide-y divide-line">
                    <div
                        v-for="link in outstanding"
                        :key="link.uuid"
                        class="flex items-baseline justify-between gap-4 p-4"
                    >
                        <div>
                            <p class="text-sm">{{ describes(link) }}</p>
                            <p class="text-2xs text-muted">
                                {{ status(link) }} &middot; expires {{ when(link.expiresAt) }}
                                <template v-if="!link.mine">
                                    &middot; issued by {{ link.createdBy ?? 'someone' }}</template
                                >
                            </p>
                        </div>

                        <div class="flex items-center gap-3 text-2xs">
                            <Link
                                v-if="link.secretUuid && names.get(link.secretUuid)"
                                :href="`/secrets/${link.secretUuid}/history`"
                                class="text-muted hover:text-ink"
                            >
                                secret
                            </Link>
                            <button
                                type="button"
                                class="text-muted hover:text-accent"
                                :aria-label="`Withdraw the link to ${describes(link)}`"
                                @click="confirming = link.uuid"
                            >
                                withdraw
                            </button>
                        </div>
                    </div>
                </div>

                <NoticePanel v-if="confirming" tone="accent" heading="withdraw this link?" class="mt-4">
                    It stops working immediately. Anyone who has already opened it keeps what they read — if
                    that has happened, rotate the credential rather than relying on this.
                    <div class="mt-3 flex gap-3">
                        <button type="button" class="btn btn-primary" @click="revoke(confirming)">
                            withdraw it
                        </button>
                        <button type="button" class="btn" @click="confirming = null">cancel</button>
                    </div>
                </NoticePanel>
            </section>

            <!--
                Kept visible until the hourly sweep removes them. "This was opened
                twice and then expired" is most of why somebody comes here, and a
                list of only live links would answer a narrower question.
            -->
            <section v-if="finished.length" class="mt-10">
                <h2 class="text-sm">finished</h2>
                <p class="mt-1 text-2xs text-muted">
                    These can no longer be opened. They are deleted outright within the hour.
                </p>

                <div class="panel mt-2 divide-y divide-line">
                    <div v-for="link in finished" :key="link.uuid" class="p-4">
                        <p class="text-sm text-muted">{{ describes(link) }}</p>
                        <p class="text-2xs text-faint">
                            {{ status(link) }} &middot; opened {{ link.viewCount }}
                            {{ link.viewCount === 1 ? 'time' : 'times' }} &middot; created
                            {{ when(link.createdAt) }}
                            <template v-if="!link.mine">
                                &middot; issued by {{ link.createdBy ?? 'someone' }}</template
                            >
                        </p>
                    </div>
                </div>
            </section>
        </template>
    </AppLayout>
</template>
