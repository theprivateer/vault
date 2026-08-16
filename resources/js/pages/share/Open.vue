<script setup lang="ts">
/**
 * The recipient's page: someone with no account, no keys, and a link.
 *
 * The page arrives holding nothing. The token and the decryption key are both in
 * the URL fragment, which no browser sends to a server, so this response could
 * not have contained the secret even if the server had wanted it to. The
 * exchange is: read the fragment, post the token, decrypt what comes back with
 * the key that never left the address bar.
 *
 * **Opening is a deliberate click, never automatic.** Revealing spends a view,
 * and a page that redeemed on mount would burn the single view of a link that
 * somebody opened by accident, or that a browser prefetched, or that was
 * restored when they reopened their tabs. The button is the consent.
 *
 * This page renders under the same strict CSP as the rest of the application. It
 * has no session, loads no Worker, and holds one plaintext for as long as the tab
 * is open — which is stated on screen, because the recipient is usually not a
 * user of this system and has no reason to assume anything about it.
 */
import { onMounted, ref } from 'vue';

import NoticePanel from '@/components/NoticePanel.vue';
import { decodeFragment, type LinkCredentials } from '@/crypto/sharelink';
import { copyForATime, CLIPBOARD_TTL_MS } from '@/lib/clipboard';
import { describeError } from '@/lib/errors';
import type { SecretPayload } from '@/lib/items';
import { revealShareLink } from '@/lib/sharelink';
import { useDocumentTitle } from '@/lib/title';

const credentials = ref<LinkCredentials | null>(null);
const payload = ref<SecretPayload | null>(null);
const viewsRemaining = ref(0);
const failure = ref('');
const busy = ref(false);
const copied = ref(false);
const revealed = ref(false);

onMounted(() => {
    /*
     | Read once, on mount, and only to find out whether there is a link here at
     | all. Nothing is sent yet.
     */
    try {
        credentials.value = decodeFragment(window.location.hash);
    } catch (error) {
        failure.value = describeError(error, 'This link is not in the expected form.');
    }
});

async function open(): Promise<void> {
    if (!credentials.value || revealed.value) {
        return;
    }

    busy.value = true;
    failure.value = '';
    // Set before the request, not after: a retry on a request that already
    // reached the server would spend a second view for one click.
    revealed.value = true;

    try {
        const result = await revealShareLink(credentials.value);

        payload.value = result.payload;
        viewsRemaining.value = result.viewsRemaining;
    } catch (error) {
        /*
         | One message for every way of failing. The server deliberately answers
         | identically whether a link never existed, expired, was withdrawn or
         | was already opened — telling them apart would say whether somebody
         | else had opened this link, which is a fact about another person.
         */
        failure.value = describeError(
            error,
            'This link cannot be opened. It may have expired, been withdrawn, or already been used.',
        );
    } finally {
        busy.value = false;
    }
}

async function copy(): Promise<void> {
    if (!payload.value) {
        return;
    }

    await copyForATime(payload.value.value);
    copied.value = true;
}

useDocumentTitle('Shared secret');
</script>

<template>
    <div class="mx-auto max-w-xl px-6 py-16">
        <h1 class="text-base font-medium">a secret was shared with you</h1>

        <NoticePanel v-if="failure" tone="accent" heading="this link did not open" class="mt-6">
            {{ failure }}
        </NoticePanel>

        <template v-else-if="payload">
            <div class="panel mt-6 space-y-3 p-4">
                <div>
                    <p class="text-2xs tracking-[0.08em] text-faint uppercase">{{ payload.type }}</p>
                    <p class="mt-1 text-sm">{{ payload.key }}</p>
                </div>

                <p class="text-sm break-all">{{ payload.value }}</p>

                <p v-if="payload.notes" class="text-2xs text-muted">{{ payload.notes }}</p>
                <p v-if="payload.url" class="text-2xs text-muted">{{ payload.url }}</p>

                <button type="button" class="btn" @click="copy">
                    {{ copied ? 'copied' : 'copy' }}
                </button>

                <p v-if="copied" class="text-2xs text-muted" role="status">
                    Cleared from the clipboard in {{ Math.round(CLIPBOARD_TTL_MS / 1000) }} seconds, if
                    nothing else has copied since.
                </p>
            </div>

            <div class="mt-6 space-y-2 text-2xs text-muted">
                <p v-if="viewsRemaining > 0">
                    This link can be opened {{ viewsRemaining }} more
                    {{ viewsRemaining === 1 ? 'time' : 'times' }}.
                </p>
                <p v-else class="text-accent">
                    That was the last opening. Reloading this page will not show it again — copy anything you
                    need now.
                </p>
                <p>
                    Save it somewhere of your own. This page holds it only until you close the tab, and the
                    server it came from has never been able to read it.
                </p>
            </div>
        </template>

        <template v-else-if="credentials">
            <NoticePanel heading="opening this uses it up" class="mt-6">
                Links like this can be opened a limited number of times, often only once. Nothing has been
                sent yet — open it when you are ready to read and save what is inside.
            </NoticePanel>

            <button type="button" class="btn btn-primary mt-6" :disabled="busy" @click="open">
                {{ busy ? 'opening…' : 'open it' }}
            </button>
        </template>

        <NoticePanel v-else heading="there is no link here" class="mt-6">
            This page needs the full link, including everything after the <code>#</code>. That part is never
            sent to the server, which is what keeps the contents private — and it is also why a link that has
            been shortened or truncated cannot be recovered.
        </NoticePanel>

        <p class="mt-10 text-2xs text-faint">
            The contents were encrypted in the sender's browser under a key carried in this link. The server
            stored an unreadable blob and a hash, and could not have read it at any point.
        </p>
    </div>
</template>
