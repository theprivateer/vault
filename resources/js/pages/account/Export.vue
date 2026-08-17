<script setup lang="ts">
/**
 * Taking everything out (Phase 12, task 3).
 *
 * This page exists because of D3. Everywhere else, this application's answer to
 * "I have lost my password" is that the data is gone and nobody can get it back
 * — which is only a defensible thing to say to somebody who was always free to
 * leave with a copy. An application that will destroy your data rather than hand
 * it to the wrong person, and gives you no way to hold it yourself, has not made
 * a security decision; it has made you dependent on it.
 *
 * Two formats, and the difference between them is stated rather than implied.
 *
 * **The archive** is the one to keep: Argon2id at deliberately painful
 * parameters, XChaCha20-Poly1305, and a header carrying every parameter needed
 * to open it. It is downloaded with a decryptor — one self-contained HTML file,
 * no network access, enforced by its own content policy — so the archive is
 * openable on a machine that has never heard of this server. That pairing is the
 * whole design: an encrypted backup only its own application can read is not a
 * backup.
 *
 * **The plaintext JSON** is the one to use and destroy. It is offered because
 * refusing to would not stop anybody — they would decrypt the archive and get
 * the same file — and pretending otherwise would only mean the warning never got
 * written. It is downloaded with the warning as the first thing inside it.
 *
 * Everything here happens after the decrypt, so all of it is in the browser. The
 * server sees one request for ciphertext it already serves a page at a time, and
 * records that it happened.
 */
import { Link } from '@inertiajs/vue3';
import { computed, ref } from 'vue';

import NoticePanel from '@/components/NoticePanel.vue';
import StrengthMeter from '@/components/StrengthMeter.vue';
import AppLayout from '@/layouts/AppLayout.vue';
import { MIN_PASSPHRASE_LENGTH } from '@/crypto/archive';
import { describeError } from '@/lib/errors';
import {
    encryptExport,
    exportFilename,
    fetchExportBundle,
    INLINE_BUDGET_BYTES,
    runExport,
    serialisePlaintext,
    type ExportDocument,
} from '@/lib/export';
import { withObjectUrl } from '@/lib/files';
import { generatePassphrase } from '@/lib/generate';
import { useSession } from '@/stores/session';
import { useDocumentTitle } from '@/lib/title';

const { isUnlocked, crypto } = useSession();

const passphrase = ref('');
const includeFiles = ref(true);
const busy = ref('');
const progress = ref({ done: 0, total: 0 });
const failure = ref('');
const summary = ref<{ vaults: number; secrets: number; files: number; omitted: number } | null>(null);

const budgetMib = Math.round(INLINE_BUDGET_BYTES / 1024 / 1024);

const passphraseTooShort = computed(
    () => passphrase.value.length > 0 && passphrase.value.length < MIN_PASSPHRASE_LENGTH,
);

const canArchive = computed(() => passphrase.value.length >= MIN_PASSPHRASE_LENGTH && busy.value === '');

function suggest(): void {
    passphrase.value = generatePassphrase({ words: 6, separator: '-', capitalise: false }).value;
}

/**
 * Saves a blob, then lets go of the handle.
 *
 * `withObjectUrl` revokes in a `finally`, which is the rule for anything holding
 * decrypted bytes — an object URL left behind outlives a lock, and the plaintext
 * export is the largest pile of decrypted bytes this application ever assembles.
 */
async function save(blob: Blob, filename: string): Promise<void> {
    await withObjectUrl(blob, async (url) => {
        const link = document.createElement('a');

        link.href = url;
        link.download = filename;
        link.click();

        // One turn of the loop before the URL is revoked: the click starts the
        // save synchronously, but the browser reads the blob afterwards.
        await new Promise((resolve) => setTimeout(resolve, 0));
    });
}

/** Decrypts the account into a document, reporting progress as it goes. */
async function collect(): Promise<ExportDocument> {
    busy.value = 'reading the account';
    progress.value = { done: 0, total: 0 };

    const bundle = await fetchExportBundle();

    busy.value = 'decrypting';

    const document = await runExport({
        client: crypto(),
        bundle,
        includeFiles: includeFiles.value,
        onProgress: (done, total) => {
            progress.value = { done, total };
        },
    });

    summary.value = {
        vaults: document.vaults.length,
        secrets: document.vaults.reduce(
            (count, vault) => count + vault.lockboxes.reduce((n, box) => n + box.secrets.length, 0),
            0,
        ),
        files: document.vaults.reduce(
            (count, vault) => count + vault.lockboxes.reduce((n, box) => n + box.files.length, 0),
            0,
        ),
        omitted: document.vaults.reduce(
            (count, vault) =>
                count + vault.lockboxes.reduce((n, box) => n + box.files.filter((f) => f.omitted).length, 0),
            0,
        ),
    };

    return document;
}

async function exportArchive(): Promise<void> {
    failure.value = '';

    try {
        const document = await collect();

        busy.value = 'encrypting — about four seconds, and the page will not respond';

        // A frame first: Argon2id at the archive's parameters blocks the main
        // thread, and without yielding the browser never paints the message
        // saying why.
        await new Promise((resolve) => requestAnimationFrame(() => setTimeout(resolve, 0)));

        const archive = encryptExport(document, passphrase.value);

        await save(
            new Blob([archive.slice()], { type: 'application/octet-stream' }),
            exportFilename('archive'),
        );
    } catch (error) {
        failure.value = describeError(error, 'The export could not be completed.');
    } finally {
        busy.value = '';
    }
}

async function exportPlaintext(): Promise<void> {
    failure.value = '';

    try {
        const document = await collect();

        busy.value = 'writing';

        await save(
            new Blob([serialisePlaintext(document)], { type: 'application/json' }),
            exportFilename('plaintext'),
        );
    } catch (error) {
        failure.value = describeError(error, 'The export could not be completed.');
    } finally {
        busy.value = '';
    }
}

useDocumentTitle('Export');
</script>

<template>
    <AppLayout>
        <Link href="/vaults" class="text-2xs text-muted hover:text-ink">&larr; back to vaults</Link>

        <h1 class="mt-4 text-base font-medium">Take a copy of everything</h1>

        <div class="mt-4 max-w-prose space-y-3 text-sm text-muted">
            <p>
                Every vault you can read, decrypted in this browser and written to a file. This exists because
                there is no password reset: an application that would rather destroy your data than hand it to
                the wrong person owes you a way to hold it yourself.
            </p>
            <p>
                It includes vaults other people have shared with you, because you hold their keys. Their
                contents will be in the file with everything else.
            </p>
        </div>

        <NoticePanel v-if="!isUnlocked" tone="accent" class="mt-6">
            Unlock first — an export means decrypting every item you have.
        </NoticePanel>

        <template v-else>
            <section class="panel mt-8 p-4">
                <h2 class="text-2xs tracking-[0.08em] text-faint uppercase">encrypted archive</h2>

                <p class="mt-3 max-w-prose text-sm text-muted">
                    The one to keep. Encrypted under a passphrase you choose here — not your master password,
                    which is deliberate: this file should stay readable after that password changes, and after
                    this account no longer exists.
                </p>

                <div class="mt-4 max-w-lg space-y-2">
                    <label for="archive-passphrase" class="block text-2xs text-muted">
                        archive passphrase
                    </label>
                    <input
                        id="archive-passphrase"
                        v-model="passphrase"
                        type="password"
                        autocomplete="new-password"
                        class="field w-full"
                        :disabled="busy !== ''"
                    />

                    <StrengthMeter :password="passphrase" />

                    <p v-if="passphraseTooShort" class="text-2xs text-accent">
                        At least {{ MIN_PASSPHRASE_LENGTH }} characters. Nothing else protects this file.
                    </p>

                    <button type="button" class="text-2xs text-accent underline" @click="suggest">
                        suggest a passphrase
                    </button>
                </div>

                <!--
                    Said here rather than in a help page, because it is the one
                    thing about this file somebody has to know at the moment they
                    make it: there is no reset for an archive either.
                -->
                <p class="mt-4 max-w-prose text-2xs text-faint">
                    Write the passphrase down somewhere separate from the archive. Nothing can recover it, and
                    nobody — including whoever runs this server — can open the file without it.
                </p>

                <label class="mt-5 flex max-w-prose items-start gap-2 text-2xs text-muted">
                    <input v-model="includeFiles" type="checkbox" :disabled="busy !== ''" class="mt-0.5" />
                    <span>
                        Include attachment contents, up to {{ budgetMib }} MiB. Anything beyond that is listed
                        by name, size and hash so you know what to fetch separately — never dropped silently.
                    </span>
                </label>

                <button
                    type="button"
                    class="btn btn-primary mt-5"
                    :disabled="!canArchive"
                    @click="exportArchive"
                >
                    export encrypted archive
                </button>

                <p class="mt-4 max-w-prose text-2xs text-muted">
                    You will need this to open it:
                    <a
                        href="/build/vault-decryptor.html"
                        download="vault-decryptor.html"
                        class="text-accent underline underline-offset-2"
                    >
                        download the offline decryptor
                    </a>
                    — one HTML file that opens an archive with no server, no network and no copy of this
                    application. Keep it wherever you keep the archive. It has no network access at all, and
                    the content policy inside the file is what enforces that rather than a promise.
                </p>
            </section>

            <section class="panel mt-6 p-4">
                <h2 class="text-2xs tracking-[0.08em] text-faint uppercase">plaintext json</h2>

                <p class="mt-3 max-w-prose text-sm text-muted">
                    The one to use and then destroy. Readable by anything — a spreadsheet, another password
                    manager, a text editor. It is offered because refusing would change nothing except whether
                    the warning got written.
                </p>

                <NoticePanel tone="accent" heading="this file is not protected by anything" class="mt-4">
                    Every password, key and card number in it is readable by any program on the computer it
                    lands on, by whatever backs that computer up, and by whoever finds the disk. Deleting it
                    does not reliably erase it.
                </NoticePanel>

                <button type="button" class="btn mt-5" :disabled="busy !== ''" @click="exportPlaintext">
                    export unencrypted json
                </button>
            </section>

            <p v-if="busy" class="mt-6 text-sm text-muted" role="status" aria-live="polite">
                {{ busy }}<span v-if="progress.total"> {{ progress.done }} / {{ progress.total }}</span
                >…
            </p>

            <NoticePanel v-if="failure" tone="accent" heading="the export stopped" class="mt-6">
                {{ failure }}
            </NoticePanel>

            <section v-if="summary && !busy" class="panel mt-6 p-4">
                <h2 class="text-2xs tracking-[0.08em] text-faint uppercase">what went in</h2>

                <dl class="mt-4 space-y-2 text-2xs">
                    <div class="flex justify-between gap-4">
                        <dt class="text-muted">vaults</dt>
                        <dd>{{ summary.vaults }}</dd>
                    </div>
                    <div class="flex justify-between gap-4">
                        <dt class="text-muted">secrets</dt>
                        <dd>{{ summary.secrets }}</dd>
                    </div>
                    <div class="flex justify-between gap-4">
                        <dt class="text-muted">attachments</dt>
                        <dd>{{ summary.files }}</dd>
                    </div>
                    <div v-if="summary.omitted" class="flex justify-between gap-4">
                        <dt class="text-muted">attachment contents left out</dt>
                        <dd class="text-accent">{{ summary.omitted }}</dd>
                    </div>
                </dl>

                <p class="mt-4 max-w-prose text-2xs text-faint">
                    The file lists what it does not contain and why — attachments over the limit, version
                    history, the audit log. An archive that was quietly partial would be worse than one that
                    is openly incomplete.
                </p>
            </section>
        </template>
    </AppLayout>
</template>
