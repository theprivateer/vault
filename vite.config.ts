import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

import inertia from '@inertiajs/vite';
import tailwindcss from '@tailwindcss/vite';
import vue from '@vitejs/plugin-vue';
import laravel from 'laravel-vite-plugin';
import { defineConfig, type Plugin } from 'vite';

const BUILD_DIRECTORY = 'public/build';

/**
 * Writes a subresource integrity hash into every manifest entry (Phase 11,
 * task 2).
 *
 * Laravel's Vite helper already emits `integrity="…"` on any script, stylesheet
 * or modulepreload whose manifest chunk carries the key; nothing produces the
 * key, so this does. Done by reading the finished files back off disk rather
 * than by hashing rollup's in-memory output, because what the browser will
 * check is the bytes that ended up in `public/`, and anything that happens
 * between rollup and disk is exactly what an integrity hash is for.
 *
 * Be clear about the size of this: it is not a defence against a compromised
 * server. The manifest lives on the same disk as the assets, so anyone who can
 * rewrite one can rewrite the other — that is adversary A3 in
 * docs/02-threat-model.md, and nothing in a browser can defend against it. What
 * this does defend against is a partial or corrupted deploy, a cache serving a
 * stale chunk against a fresh manifest, and the day this application stops
 * being served entirely from one origin.
 *
 * SHA-384 rather than SHA-256 because it is the middle option the spec defines
 * and browsers pick the strongest hash offered; there is no reason to offer the
 * weakest.
 */
function subresourceIntegrity(): Plugin {
    return {
        name: 'vault:subresource-integrity',
        apply: 'build',
        // After the manifest has been written, which is the file being edited.
        enforce: 'post',
        closeBundle() {
            const manifestPath = resolve(BUILD_DIRECTORY, 'manifest.json');

            if (!existsSync(manifestPath)) {
                return;
            }

            const manifest = JSON.parse(readFileSync(manifestPath, 'utf8')) as Record<
                string,
                { file: string; css?: string[]; integrity?: string }
            >;

            /*
             | A stylesheet imported from JavaScript appears only as a filename
             | inside its importer's `css` array — it gets no entry of its own.
             | Laravel resolves those by searching the manifest for a chunk whose
             | `file` matches, finds nothing, and renders the tag with no
             | integrity attribute. Giving each one an entry is what makes the
             | stylesheet covered rather than quietly exempt.
             */
            for (const chunk of Object.values(manifest)) {
                for (const css of chunk.css ?? []) {
                    manifest[css] ??= { file: css };
                }
            }

            for (const chunk of Object.values(manifest)) {
                const digest = createHash('sha384')
                    .update(readFileSync(join(BUILD_DIRECTORY, chunk.file)))
                    .digest('base64');

                chunk.integrity = `sha384-${digest}`;
            }

            writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
        },
    };
}

export default defineConfig({
    plugins: [
        laravel({
            input: ['resources/js/app.ts'],
            refresh: true,
        }),
        tailwindcss(),
        vue({
            template: {
                transformAssetUrls: {
                    base: null,
                    includeAbsolute: false,
                },
            },
        }),
        inertia(),
        subresourceIntegrity(),
    ],
    server: {
        watch: {
            ignored: ['**/storage/framework/views/**'],
        },
    },
});
