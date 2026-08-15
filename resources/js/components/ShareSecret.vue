<script setup lang="ts">
/**
 * Handing one secret to somebody with no account.
 *
 * The URL this produces is the credential. The server never sees the half after
 * the `#` — not the link key, not the bearer token — so once this panel is
 * closed the link exists nowhere but wherever the user pasted it. That is worth
 * saying on screen rather than only in a comment, because it is also the
 * failure mode: nobody can re-issue this link, including us.
 *
 * The caveats below are not boilerplate. A link in a chat window is a credential
 * in a chat window, and it will be in that history long after the link stops
 * working.
 */
import { computed, ref } from 'vue';

import NoticePanel from '@/components/NoticePanel.vue';
import { generateLinkCredentials, shareUrl } from '@/crypto/sharelink';
import { copyForATime } from '@/lib/clipboard';
import { describeError } from '@/lib/errors';
import type { SecretPayload } from '@/lib/items';
import { createShareLink } from '@/lib/sharelink';

const props = defineProps<{
    secretUuid: string;
    payload: SecretPayload;
    defaultHours: number;
    maxHours: number;
    maxViews: number;
}>();

const emit = defineEmits<{ close: [] }>();

const hours = ref(props.defaultHours);
const views = ref(1);
const url = ref('');
const failure = ref('');
const busy = ref(false);
const copied = ref(false);

const expiresOn = computed(() => new Date(Date.now() + hours.value * 3_600_000).toLocaleString());

async function create(): Promise<void> {
    busy.value = true;
    failure.value = '';

    try {
        /*
         | Generated here and never sent. `createShareLink` posts the token's
         | *hash* and the sealed payload; the token and the key go straight into
         | the fragment below. The server therefore cannot open the payload and
         | cannot redeem the link, even from its own database.
         */
        const credentials = generateLinkCredentials();

        await createShareLink(
            props.secretUuid,
            props.payload,
            { expiresInHours: hours.value, maxViews: views.value },
            credentials,
        );

        url.value = shareUrl(window.location.origin, credentials);
    } catch (error) {
        failure.value = describeError(error, 'The link could not be created.');
    } finally {
        busy.value = false;
    }
}

async function copy(): Promise<void> {
    await copyForATime(url.value);
    copied.value = true;
}
</script>

<template>
    <div class="panel space-y-6 p-4">
        <div class="flex items-baseline justify-between gap-4">
            <h3 class="text-sm">one-time link</h3>
            <button type="button" class="text-2xs text-muted hover:text-ink" @click="emit('close')">
                close
            </button>
        </div>

        <template v-if="url === ''">
            <NoticePanel heading="what this does">
                This copies the secret, re-encrypts it under a brand new key, and puts that key in the link —
                not on the server. Anyone who has the link can read it; nobody else can, and neither can we.
                It is a way to send one credential to one person, not a way to give somebody access to this
                vault.
            </NoticePanel>

            <div>
                <label class="label" for="share-hours">expires in &middot; {{ hours }} hours</label>
                <input
                    id="share-hours"
                    v-model.number="hours"
                    type="range"
                    min="1"
                    :max="maxHours"
                    class="w-full"
                />
                <p class="mt-1 text-2xs text-muted">{{ expiresOn }}</p>
            </div>

            <div>
                <label class="label" for="share-views">opens &middot; {{ views }}</label>
                <input
                    id="share-views"
                    v-model.number="views"
                    type="range"
                    min="1"
                    :max="maxViews"
                    class="w-full"
                />
                <p class="mt-1 text-2xs text-muted">
                    One is usually right. Allow more if the recipient may open it on a second device — a
                    reload spends one.
                </p>
            </div>

            <p v-if="failure" class="text-2xs text-accent">{{ failure }}</p>

            <button type="button" class="btn btn-primary" :disabled="busy" @click="create">
                {{ busy ? 'creating…' : 'create link' }}
            </button>
        </template>

        <template v-else>
            <NoticePanel tone="accent" heading="copy this now — it is not shown again">
                The part after the <code>#</code> never reached the server, so this link cannot be recovered
                from anywhere. Close this panel without copying it and the only remedy is to make another one.
            </NoticePanel>

            <p class="text-2xs break-all text-ink" aria-live="polite">{{ url }}</p>

            <button type="button" class="btn btn-primary" @click="copy">
                {{ copied ? 'copied' : 'copy link' }}
            </button>

            <div class="space-y-2 text-2xs text-muted">
                <p>
                    Send it somewhere you would be willing to send the password itself. The link is the
                    credential, and it will sit in that chat history long after it stops working.
                </p>
                <p>
                    Link previews cannot spend a view — an unfurler only ever fetches the page, and the token
                    is in the part of the URL browsers do not transmit.
                </p>
            </div>
        </template>
    </div>
</template>
