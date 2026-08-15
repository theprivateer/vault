<script setup lang="ts">
/**
 * File attachments for one lockbox.
 *
 * Uploads and downloads both run entirely in this tab: the bytes are encrypted
 * chunk by chunk in the Worker on the way out and decrypted the same way on the
 * way back, and the server sees nothing but opaque blobs keyed by a random UUID.
 * The filename in this list came out of an encrypted manifest a moment ago —
 * there is no column anywhere that holds it.
 *
 * **Saving a file is a deliberate act, not a side effect of viewing one.** The
 * download button assembles a Blob and hands it to the browser through an object
 * URL that is revoked as soon as the click has happened; the preview does the
 * same for an `<img>` and revokes on load. Nothing keeps a live handle to
 * decrypted content around, because such a handle would outlive a lock.
 */
import { computed, onBeforeUnmount, ref } from 'vue';

import type { CryptoClient } from '@/crypto/worker/client';
import NoticePanel from '@/components/NoticePanel.vue';
import { describeError } from '@/lib/errors';
import { downloadFile, isPreviewable, uploadFile, withObjectUrl, type FileManifest } from '@/lib/files';
import { onLock } from '@/stores/lock';
import type { OpenedFile } from '@/stores/vault';

const props = defineProps<{
    files: OpenedFile[];
    vaultUuid: string;
    lockboxUuid: string;
    canWrite: boolean;
    crypto: () => CryptoClient;
}>();

const emit = defineEmits<{ changed: []; remove: [uuid: string] }>();

const failure = ref('');
const busy = ref('');
const progress = ref({ done: 0, total: 0 });
const previewing = ref<string | null>(null);
const previewUrl = ref('');
const previewText = ref('');
const input = ref<HTMLInputElement | null>(null);

const percent = computed(() =>
    progress.value.total === 0 ? 0 : Math.round((progress.value.done / progress.value.total) * 100),
);

/** Bytes, at the resolution anybody actually reads them at. */
function humanSize(bytes: number): string {
    const units = ['B', 'KiB', 'MiB', 'GiB'];
    let value = bytes;
    let unit = 0;

    while (value >= 1024 && unit < units.length - 1) {
        value /= 1024;
        unit += 1;
    }

    return `${value < 10 && unit > 0 ? value.toFixed(1) : Math.round(value)} ${units[unit]}`;
}

async function upload(event: Event): Promise<void> {
    const chosen = (event.target as HTMLInputElement).files?.[0];

    if (!chosen) {
        return;
    }

    failure.value = '';
    busy.value = `Encrypting and uploading ${chosen.name}`;
    progress.value = { done: 0, total: 1 };

    try {
        await uploadFile({
            client: props.crypto(),
            vaultUuid: props.vaultUuid,
            lockboxUuid: props.lockboxUuid,
            file: chosen,
            onProgress: (done, total) => (progress.value = { done, total }),
        });

        emit('changed');
    } catch (error) {
        failure.value = describeError(error, 'The file could not be uploaded.');
    } finally {
        busy.value = '';
        progress.value = { done: 0, total: 0 };

        // Cleared so choosing the same file twice fires a change event again,
        // which it otherwise would not after a failed attempt.
        if (input.value) {
            input.value.value = '';
        }
    }
}

/** Decrypts the whole file and hands it to the browser to save. */
async function save(entry: OpenedFile, manifest: FileManifest): Promise<void> {
    failure.value = '';
    busy.value = `Downloading and decrypting ${manifest.filename}`;
    progress.value = { done: 0, total: manifest.chunkCount };

    try {
        const blob = await open(entry, manifest);

        await withObjectUrl(blob, async (url) => {
            const link = document.createElement('a');

            link.href = url;
            link.download = manifest.filename;
            link.click();

            /*
             | One turn of the event loop before the URL is revoked. The click
             | starts the save synchronously but the browser reads the blob
             | afterwards, and revoking in the same tick cancels it.
             */
            await new Promise((resolve) => setTimeout(resolve, 0));
        });
    } catch (error) {
        failure.value = describeError(error, 'The file could not be downloaded.');
    } finally {
        busy.value = '';
        progress.value = { done: 0, total: 0 };
    }
}

/**
 * Shows an image or a text file inline.
 *
 * Only the types in `isPreviewable`, which is a short allow-list rather than a
 * block-list: an SVG is an image and also a document that can run script, and
 * `text/html` is the same problem wearing a different name. Anything else is
 * downloaded rather than rendered.
 */
async function preview(entry: OpenedFile, manifest: FileManifest): Promise<void> {
    if (previewing.value === entry.record.uuid) {
        closePreview();

        return;
    }

    closePreview();
    failure.value = '';
    busy.value = `Decrypting ${manifest.filename}`;
    progress.value = { done: 0, total: manifest.chunkCount };

    try {
        const blob = await open(entry, manifest);

        previewing.value = entry.record.uuid;

        if (manifest.mime === 'text/plain') {
            previewText.value = await blob.text();
        } else {
            /*
             | The one place a URL outlives its callback, and it is deliberate:
             | an <img> needs the handle for as long as it is on screen. It is
             | revoked when the image loads and when the preview closes, and
             | nothing else is ever given one.
             */
            previewUrl.value = URL.createObjectURL(blob);
        }
    } catch (error) {
        failure.value = describeError(error, 'The file could not be decrypted.');
    } finally {
        busy.value = '';
        progress.value = { done: 0, total: 0 };
    }
}

function open(entry: OpenedFile, manifest: FileManifest): Promise<Blob> {
    return downloadFile({
        client: props.crypto(),
        vaultUuid: props.vaultUuid,
        uuid: entry.record.uuid,
        manifest,
        wrappedItemKey: entry.record.wrappedItemKey,
        onProgress: (done, total) => (progress.value = { done, total }),
    });
}

/**
 * Releases the handle the moment the image has been decoded.
 *
 * The picture stays on screen — the browser has the pixels — while the
 * `blob:` URL stops resolving, so nothing else on the page can fetch the
 * decrypted bytes back out of it.
 */
function imageLoaded(): void {
    if (previewUrl.value) {
        URL.revokeObjectURL(previewUrl.value);
    }
}

function closePreview(): void {
    if (previewUrl.value) {
        URL.revokeObjectURL(previewUrl.value);
        previewUrl.value = '';
    }

    previewText.value = '';
    previewing.value = null;
}

/*
 | A preview is decrypted content on screen, so it goes when the vault does.
 | Locking wipes the store and terminates the Worker; a rendered image and a
 | paragraph of someone's notes left behind would make "locked" a lie about the
 | part of the screen anybody is actually looking at.
 */
onLock(closePreview);

onBeforeUnmount(closePreview);
</script>

<template>
    <section>
        <div class="flex items-baseline justify-between gap-4">
            <h2 class="text-2xs tracking-[0.08em] text-faint uppercase">attachments</h2>

            <label v-if="canWrite" class="btn cursor-pointer text-2xs">
                attach a file
                <input ref="input" type="file" class="sr-only" @change="upload" />
            </label>
        </div>

        <NoticePanel v-if="failure" tone="accent" heading="file error" class="mt-3">
            {{ failure }}
        </NoticePanel>

        <div
            v-if="busy"
            class="mt-3"
            role="status"
            aria-live="polite"
            :aria-label="`${busy}: ${progress.done} of ${progress.total} chunks`"
        >
            <p class="text-2xs text-muted">{{ busy }} — {{ progress.done }} / {{ progress.total }}…</p>
            <div class="mt-2 h-px w-full bg-line">
                <div class="h-px bg-accent" :style="{ width: `${percent}%` }" />
            </div>
        </div>

        <div v-if="files.length" class="panel mt-3 divide-y divide-line">
            <div v-for="entry in files" :key="entry.record.uuid" class="p-4">
                <NoticePanel v-if="entry.error" tone="accent" heading="integrity failure">
                    {{ entry.error }}
                </NoticePanel>

                <div v-else-if="entry.payload" class="space-y-2">
                    <div class="flex items-baseline justify-between gap-4">
                        <div>
                            <p class="text-sm break-all">{{ entry.payload.filename }}</p>
                            <p class="text-2xs text-faint">
                                {{ humanSize(entry.payload.plaintextSize) }} ·
                                {{ entry.payload.mime || 'unknown type' }}
                            </p>
                        </div>

                        <div class="flex items-center gap-3 text-2xs">
                            <button
                                v-if="isPreviewable(entry.payload)"
                                type="button"
                                class="text-muted hover:text-ink"
                                :aria-expanded="previewing === entry.record.uuid"
                                :aria-label="`Preview ${entry.payload.filename}`"
                                @click="preview(entry, entry.payload)"
                            >
                                {{ previewing === entry.record.uuid ? 'close' : 'preview' }}
                            </button>
                            <button
                                type="button"
                                class="text-muted hover:text-ink"
                                :aria-label="`Download ${entry.payload.filename}`"
                                @click="save(entry, entry.payload)"
                            >
                                download
                            </button>
                            <button
                                v-if="canWrite"
                                type="button"
                                class="text-muted hover:text-accent"
                                :aria-label="`Delete ${entry.payload.filename}`"
                                @click="emit('remove', entry.record.uuid)"
                            >
                                delete
                            </button>
                        </div>
                    </div>

                    <template v-if="previewing === entry.record.uuid">
                        <img
                            v-if="previewUrl"
                            :src="previewUrl"
                            :alt="entry.payload.filename"
                            class="mt-2 max-h-96 max-w-full border border-line"
                            @load="imageLoaded"
                        />
                        <!-- Rendered as text, never as markup: v-html on
                             decrypted content is the shortest path to XSS. -->
                        <pre
                            v-else
                            class="mt-2 max-h-96 overflow-auto border border-line p-3 text-2xs whitespace-pre-wrap"
                            >{{ previewText }}</pre>
                    </template>
                </div>
            </div>
        </div>

        <p v-else class="mt-3 text-2xs text-muted">Nothing attached to this lockbox.</p>
    </section>
</template>
