/**
 * The two client-side security requirements that are properties of the whole
 * bundle rather than of any one module.
 *
 * **SR7** — key material never reaches `localStorage`, `sessionStorage`,
 * IndexedDB or a cookie. Until Phase 11 this held "by construction": nothing in
 * `resources/js` called any of those APIs. That is a true statement about the
 * code and not a test, and the difference matters, because the way it stops
 * being true is somebody adding a cache to a store at four in the afternoon.
 *
 * **Trusted Types** — the CSP enforces `require-trusted-types-for 'script'`
 * with no default policy, which means an assignment to `innerHTML` anywhere in
 * this application throws at runtime in a real browser and nowhere else. Node
 * has no Trusted Types, so the test suite cannot catch one by running the code;
 * it has to catch it by reading it.
 *
 * Both are checked twice, and deliberately so:
 *
 *   - a sweep of the source, which catches the call that is never reached in a
 *     test but ships anyway;
 *   - a run of the real crypto client against traps, which catches the call
 *     that a sweep cannot see because it went through a dependency or a
 *     computed property name.
 *
 * Neither replaces the other. This is still not a browser — a genuine end-to-end
 * check against a real Worker in a real page is the honest form of both, and
 * docs/02-threat-model.md says so rather than claiming this is that.
 *
 * **And the sweep has a blind spot that a deployment found.** It reads
 * `resources/js`, so a sink inside a *dependency* is invisible to it. Inertia's
 * head manager builds every element it owns by assigning to `template.innerHTML`,
 * and it owns a `<title>` the moment `createInertiaApp` is given a `title`
 * callback that returns something for an empty string. Every assertion in this
 * file passed while the shipped bundle threw on its first paint in a browser
 * enforcing the header. The guard for that specific trigger is below; the
 * general answer is still an end-to-end suite.
 */
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterEach, describe, expect, it } from 'vitest';

import { toBase64 } from '@/lib/bytes';
import { randomBytes } from './crypto/primitives';
import { CryptoClient } from './crypto/worker/client';
import { installHandler, type WorkerScope } from './crypto/worker/handler';
import type { Reply, Request } from './crypto/worker/protocol';
import { vaultKeyHandle } from './crypto/worker/protocol';

const SOURCE_ROOT = fileURLToPath(new URL('.', import.meta.url));

/**
 * Removes comments, which is the whole trick.
 *
 * The same lesson tests/Feature/NoServerDecryptionTest.php learned on the
 * server: a sweep that cannot tell a call from a prose mention fires on the
 * docblock that exists to explain why the call is absent. Several files here
 * discuss `innerHTML` at length precisely because they are the ones that
 * removed it.
 */
function stripComments(source: string): string {
    return source
        .replace(/\/\*[\s\S]*?\*\//g, '')
        .replace(/<!--[\s\S]*?-->/g, '')
        .replace(/(^|[^:])\/\/.*$/gm, '$1');
}

/** Every `.ts` and `.vue` file under resources/js, stripped of its comments. */
function sourceFiles(): Array<{ path: string; code: string }> {
    const files: Array<{ path: string; code: string }> = [];

    const walk = (directory: string): void => {
        for (const entry of readdirSync(directory, { withFileTypes: true })) {
            const path = join(directory, entry.name);

            if (entry.isDirectory()) {
                walk(path);
                continue;
            }

            if (!/\.(ts|vue)$/.test(entry.name) || entry.name.endsWith('.test.ts')) {
                continue;
            }

            files.push({
                path: path.slice(SOURCE_ROOT.length),
                code: stripComments(readFileSync(path, 'utf8')),
            });
        }
    };

    walk(SOURCE_ROOT);

    return files;
}

/** Files whose stripped source mentions any of the given patterns. */
function mentioning(patterns: readonly RegExp[]): string[] {
    return sourceFiles()
        .filter(({ code }) => patterns.some((pattern) => pattern.test(code)))
        .map(({ path }) => path);
}

describe('SR7: key material never reaches persistent storage', () => {
    /*
     | Note what is *not* on this list: `sessionStorage` is no safer than
     | `localStorage` here. It survives a reload, which is exactly long enough
     | to outlive the lock this application applies on idle, and it is readable
     | by any script that reaches the page — which is the adversary the lock
     | exists for.
     */
    it('calls no storage API anywhere in the client', () => {
        expect(
            mentioning([
                /\blocalStorage\b/,
                /\bsessionStorage\b/,
                /\bindexedDB\b/i,
                /\bcaches\b/,
                /\bdocument\.cookie\s*=/,
            ]),
        ).toEqual([]);
    });

    /*
     | The one cookie interaction in the client, and it is a read: lib/http.ts
     | lifts the XSRF token out of the cookie Laravel set, because that is how
     | the framework's CSRF check works. Asserted rather than left as an
     | exception in the pattern above, so that the exemption is visible and a
     | second reader is not left wondering whether the sweep has a hole.
     */
    it('reads the csrf cookie and nothing else', () => {
        expect(mentioning([/document\.cookie/])).toEqual(['lib/http.ts']);
    });

    /*
     | The sweep above reads the code; this runs it. A key written through a
     | dependency, or through a property name assembled at runtime, is invisible
     | to a regular expression and lands squarely on these traps.
     */
    it('writes nothing to storage while deriving, sealing and opening', async () => {
        const writes: string[] = [];

        const trap = (name: string): Storage => ({
            getItem: () => null,
            key: () => null,
            length: 0,
            clear: () => {},
            removeItem: () => {},
            setItem: (key: string) => writes.push(`${name}.${key}`),
        });

        Object.assign(globalThis, {
            localStorage: trap('localStorage'),
            sessionStorage: trap('sessionStorage'),
            indexedDB: {
                open: () => {
                    writes.push('indexedDB.open');

                    throw new Error('indexedDB is not available to this application');
                },
            },
            document: {
                set cookie(value: string) {
                    writes.push(`cookie:${value}`);
                },
                get cookie(): string {
                    return '';
                },
            },
        });

        const crypto = new CryptoClient(() => new FakeWorker() as unknown as Worker);
        const vault = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f0';

        await crypto.register({
            password: 'correct horse',
            kdfSalt: randomBytes(16),
            kdfParams: { m: 8, t: 1, p: 1 },
            uuid: vault,
        });

        await crypto.generateInto(vaultKeyHandle(vault));

        const aad = { context: 'secret.payload', subject: vault, version: 2 } as const;
        const plaintext = new TextEncoder().encode('hunter2');

        const sealed = await crypto.seal(vaultKeyHandle(vault), plaintext, aad);
        const opened = await crypto.open(vaultKeyHandle(vault), sealed, aad);

        // The round trip is here so that a run which quietly did nothing cannot
        // pass by writing nothing.
        expect(toBase64(opened)).toBe(toBase64(plaintext));
        expect(writes).toEqual([]);
    });
});

describe('trusted types: the sinks the CSP forbids', () => {
    /*
     | `document.title` is deliberately absent from this list. It is a plain
     | string property, not a Trusted Types sink, which is the reason
     | lib/title.ts exists at all — Inertia's `<Head>` sets the same title by
     | assigning `innerHTML` on a template element, and under this CSP that
     | throws on every navigation.
     */
    it('assigns nothing to a markup or script sink', () => {
        expect(
            mentioning([
                /\.innerHTML\b/,
                /\.outerHTML\s*=/,
                /insertAdjacentHTML/,
                /document\.write\b/,
                /\beval\s*\(/,
                /new\s+Function\s*\(/,
            ]),
        ).toEqual([]);
    });

    /*
     | `v-html` is banned by ESLint as well, and named here because the lint
     | rule is about XSS while this is about the page still working: with no
     | default policy, Vue's `v-html` path throws rather than rendering.
     */
    /*
     | The trigger, guarded specifically because the sweep above cannot see it.
     |
     | Inertia's `collect()` calls the title callback with an empty string to
     | decide whether it owns a title element; anything truthy comes back as
     | `<title data-inertia="">…</title>` and is then built through
     | `template.innerHTML`, on start-up and on every navigation. With no
     | callback it collects nothing and never reaches the renderer.
     |
     | The suffix rule lives in lib/title.ts, which assigns `document.title` —
     | a plain string property and not a sink at all.
     */
    it('gives Inertia no title callback, so its head manager owns no element', () => {
        const app = stripComments(readFileSync(join(SOURCE_ROOT, 'app.ts'), 'utf8'));

        expect(app).toContain('createInertiaApp');
        expect(app).not.toMatch(/\btitle\s*:/);
    });

    it('uses no v-html', () => {
        expect(mentioning([/v-html/])).toEqual([]);
    });

    /*
     | A sweep that passes because it can no longer see anything is worse than
     | no sweep, and comment-stripping is exactly the change that produces one:
     | make the block-comment pattern slightly too greedy and every file becomes
     | empty and every assertion above goes green.
     */
    it('still sees a sink once the comments are gone', () => {
        const code = stripComments(`
            /* This file must never assign to innerHTML. */
            // Not even here: element.innerHTML = value.
            <!-- nor in a template comment: el.innerHTML = value -->
            function render(el: HTMLElement, value: string) { el.innerHTML = value; }
        `);

        expect(code).toContain('el.innerHTML = value;');
        expect(code.match(/innerHTML/g)).toHaveLength(1);
    });
});

/** The in-process Worker stand-in, as crypto/worker/client.test.ts builds it. */
class FakeWorker implements Pick<Worker, 'postMessage' | 'terminate' | 'onmessage' | 'onerror'> {
    onmessage: ((event: MessageEvent<Reply>) => void) | null = null;

    onerror: ((event: unknown) => void) | null = null;

    private readonly scope: WorkerScope;

    constructor() {
        this.scope = {
            onmessage: null,
            postMessage: (reply: Reply) => {
                queueMicrotask(() => this.onmessage?.({ data: reply } as MessageEvent<Reply>));
            },
        };

        installHandler(this.scope);
    }

    postMessage(message: { id: number; request: Request }): void {
        this.scope.onmessage?.({ data: structuredClone(message) });
    }

    terminate(): void {}
}

afterEach(() => {
    for (const global of ['localStorage', 'sessionStorage', 'indexedDB', 'document']) {
        Reflect.deleteProperty(globalThis, global);
    }
});
