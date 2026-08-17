/**
 * The offline decryptor (Phase 12, task 3).
 *
 * One HTML file with everything inlined, meant to be saved next to an archive
 * and kept. Its entire reason for existing is the case where this application
 * is not available: the server switched off, the project abandoned, the operator
 * no longer trusted, the account long since deleted. An encrypted archive that
 * could only be opened by the thing whose disappearance it insures against is
 * not a backup, it is a hostage note with a nicer format.
 *
 * So this page has no network code at all, and is served under a Content
 * Security Policy of its own that forbids any — `default-src 'none'`, written
 * into the file it ships as. That is a stronger claim than "it does not
 * exfiltrate your secrets": the browser will not let it, and anybody who wants
 * to check can read the policy in the first twenty lines of the file rather
 * than auditing the bundle underneath.
 *
 * It imports from `crypto/` directly, so there is exactly one implementation of
 * the archive format in this repository. A second one, written for the
 * decryptor, would be a copy that drifts — and the day it drifted would be the
 * day somebody needed it.
 *
 * No framework. Not for size: Vue's runtime would be a rounding error next to
 * Argon2id's memory. It is that this file has to still work in a browser nobody
 * has written yet, and plain DOM calls are the part of the platform least likely
 * to have moved. `textContent` throughout, never `innerHTML`, which the sweep in
 * security.test.ts enforces here as everywhere else.
 */
import { openArchive, readArchiveHeader } from '@/crypto/archive';
import { CryptoError } from '@/crypto/errors';
import type { KdfParams } from '@/crypto/primitives';

const ORANGE = '#ff7a1a';

function element<K extends keyof HTMLElementTagNameMap>(
    tag: K,
    text = '',
    style = '',
): HTMLElementTagNameMap[K] {
    const node = document.createElement(tag);
    node.textContent = text;
    node.style.cssText = style;

    return node;
}

/** Read out of the archive, never assumed — that is what the header is for. */
function describeParams(params: KdfParams): string {
    const memory = params.m >= 1024 ? `${Math.round(params.m / 1024)} MiB` : `${params.m} KiB`;

    return `Argon2id, ${memory} memory, ${params.t} passes, parallelism ${params.p}`;
}

function describe(error: unknown): string {
    if (error instanceof CryptoError) {
        return error.message;
    }

    return error instanceof Error ? error.message : 'The archive could not be opened.';
}

function build(): void {
    document.body.style.cssText =
        'margin:0;padding:2.5rem 1.5rem;background:#0c0c0c;color:#e8e8e8;' +
        'font:14px/1.6 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace';

    const main = element('main', '', 'max-width:62rem;margin:0 auto');
    document.body.append(main);

    main.append(
        element('h1', 'Vault archive decryptor', 'font-size:1.1rem;font-weight:600;margin:0 0 0.75rem'),
    );
    main.append(
        element(
            'p',
            'Opens a .vaultarchive file. Everything happens in this page — it has no network access, ' +
                'and the policy in its own header is what stops it acquiring any. Keep it with the archive.',
            'margin:0 0 2rem;color:#9a9a9a;max-width:52rem',
        ),
    );

    const fileInput = element('input');
    fileInput.type = 'file';
    fileInput.accept = '.vaultarchive,application/octet-stream';
    fileInput.style.cssText = 'display:block;margin-bottom:1.25rem;color:#e8e8e8';

    const passphrase = element('input');
    passphrase.type = 'password';
    passphrase.placeholder = 'archive passphrase';
    passphrase.autocomplete = 'off';
    passphrase.style.cssText =
        'display:block;width:100%;max-width:34rem;padding:0.55rem 0.7rem;margin-bottom:1.25rem;' +
        'background:#161616;border:1px solid #333;color:#e8e8e8;font:inherit';

    const button = element('button', 'open archive');
    button.type = 'button';
    button.style.cssText =
        `padding:0.55rem 1.1rem;background:transparent;border:1px solid ${ORANGE};color:${ORANGE};` +
        'font:inherit;cursor:pointer';

    const status = element('p', '', 'margin:1.5rem 0 0;min-height:1.6rem');
    const details = element('pre', '', 'margin:0.5rem 0 0;color:#9a9a9a;white-space:pre-wrap;font:inherit');

    const output = element('textarea');
    output.readOnly = true;
    output.spellcheck = false;
    output.style.cssText =
        'display:none;width:100%;height:26rem;margin-top:1.5rem;padding:0.75rem;background:#161616;' +
        'border:1px solid #333;color:#e8e8e8;font:inherit;resize:vertical';

    main.append(fileInput, passphrase, button, status, details, output);

    let archive: Uint8Array | null = null;

    fileInput.addEventListener('change', () => {
        const file = fileInput.files?.[0];
        output.style.display = 'none';
        status.textContent = '';
        details.textContent = '';
        archive = null;

        if (!file) {
            return;
        }

        file.arrayBuffer()
            .then((buffer) => {
                const bytes = new Uint8Array(buffer);
                // Reading the header before anybody types a passphrase is the
                // point: it confirms this is the right file, and states the cost
                // parameters, before several seconds are spent on the wrong one.
                const header = readArchiveHeader(bytes);

                archive = bytes;
                status.textContent = `Archive ${header.uuid}`;
                details.textContent = `${describeParams(header.params)}\n${bytes.length.toLocaleString()} bytes`;
            })
            .catch((error: unknown) => {
                status.style.color = ORANGE;
                status.textContent = describe(error);
            });
    });

    button.addEventListener('click', () => {
        if (!archive) {
            status.style.color = ORANGE;
            status.textContent = 'Choose an archive first.';

            return;
        }

        const bytes = archive;
        status.style.color = '#e8e8e8';
        status.textContent = 'Deriving the key. A few seconds, and the page will not respond…';
        output.style.display = 'none';

        /*
         | A frame before the work starts. Argon2id at these parameters blocks
         | the main thread for seconds, and without yielding first the browser
         | never paints the message that explains why it has stopped responding.
         | A Worker would be the tidier answer and would mean a second file or an
         | inlined blob URL, which is the one thing this page must not need.
         */
        requestAnimationFrame(() => {
            setTimeout(() => {
                try {
                    const plaintext = new TextDecoder().decode(openArchive(passphrase.value, bytes));

                    output.value = plaintext;
                    output.style.display = 'block';
                    status.textContent = 'Opened. The contents are below, and are not encrypted.';
                    details.textContent =
                        'Select all and copy, or save this page’s text somewhere you are prepared to ' +
                        'lose control of. Close the tab when you are done.';
                } catch (error) {
                    status.style.color = ORANGE;
                    status.textContent = 'Wrong passphrase, or this archive has been altered.';
                    details.textContent = describe(error);
                }
            }, 0);
        });
    });
}

build();
