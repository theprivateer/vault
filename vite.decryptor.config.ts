import { createHash } from 'node:crypto';
import { readFileSync, rmSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { defineConfig, type Plugin } from 'vite';

/**
 * The offline decryptor is built to one self-contained HTML file.
 *
 * Not a page of the application, and deliberately not part of the Vite manifest:
 * this artefact is downloaded once and kept for years, alongside an archive it
 * may have to open long after this server has gone. Anything it referenced by
 * URL — a stylesheet, a chunk, a font — would be a dead link on the day it
 * mattered, so everything is inlined and the file has no external references at
 * all.
 *
 * Inlining is done here rather than with a plugin because it is fifteen lines
 * and a dependency approved for one build step is a dependency forever.
 *
 * Output: public/build/vault-decryptor.html. Served by the export page as a
 * download, never loaded as part of the application.
 */
const OUTPUT = 'public/build/vault-decryptor.html';

const BUNDLE = 'public/build/decryptor.js';

/**
 * The page's own Content Security Policy, carried in the file.
 *
 * `default-src 'none'` is the load-bearing line, and it is enforced whether the
 * file is opened from a disk, a USB stick or an email attachment. It means the
 * decryptor cannot fetch, cannot post, cannot load an image, cannot open a
 * socket — so "this page does not send your secrets anywhere" is checkable by
 * reading twenty lines rather than by auditing a bundle.
 *
 * The script is allowed by the SHA-256 of its own contents rather than by
 * 'unsafe-inline'. Editing so much as a byte of the script without recomputing
 * the hash produces a page that refuses to run, which is the correct failure for
 * a file whose whole job is handling somebody's plaintext.
 *
 * `style-src 'unsafe-inline'` is the one concession, and it is a small one: the
 * page sets element styles from script, which is a style-src decision rather
 * than a script-src one. It cannot fetch a stylesheet — default-src forbids it —
 * so the worst an injected style could do here is misrepresent the page, on a
 * page with no network access to misrepresent it into.
 */
function policy(scriptHash: string): string {
    return [
        "default-src 'none'",
        `script-src 'sha256-${scriptHash}'`,
        "style-src 'unsafe-inline'",
        "form-action 'none'",
        "base-uri 'none'",
    ].join('; ');
}

function inlineSingleFile(): Plugin {
    return {
        name: 'vault:inline-decryptor',
        apply: 'build',
        enforce: 'post',
        closeBundle() {
            const script = readFileSync(resolve(BUNDLE), 'utf8');
            const hash = createHash('sha256').update(script, 'utf8').digest('base64');

            const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="${policy(hash)}">
<title>Vault archive decryptor</title>
</head>
<body>
<noscript>This page needs JavaScript: decrypting the archive is all it does.</noscript>
<script type="module">${script}</script>
</body>
</html>
`;

            writeFileSync(resolve(OUTPUT), html);

            // The bare bundle is an intermediate. Leaving it in public/build
            // would publish a second, policy-free copy of the same code.
            rmSync(resolve(BUNDLE));
        },
    };
}

export default defineConfig({
    publicDir: false,
    plugins: [inlineSingleFile()],
    resolve: {
        alias: { '@': resolve(import.meta.dirname, 'resources/js') },
    },
    build: {
        // Must not wipe the main build's output.
        emptyOutDir: false,
        outDir: 'public/build',
        target: 'es2022',
        // One file, so there is nothing left to resolve at runtime.
        modulePreload: false,
        rollupOptions: {
            input: 'resources/js/decryptor/main.ts',
            output: {
                format: 'es',
                entryFileNames: 'decryptor.js',
                codeSplitting: false,
            },
        },
    },
});
