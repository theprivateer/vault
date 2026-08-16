import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { effectScope, nextTick, ref } from 'vue';

import { formatTitle, useDocumentTitle } from './title';

/*
 | `document.title` is the whole reason this module exists: it is a plain string
 | property rather than a Trusted Types sink, which is what let Inertia's <Head>
 | be removed instead of granted a policy. The suite runs under `node`, so the
 | one property being written is stubbed rather than a DOM being imported.
 */
const original = Reflect.getOwnPropertyDescriptor(globalThis, 'document');

beforeEach(() => {
    Object.defineProperty(globalThis, 'document', {
        value: { title: '' },
        configurable: true,
        writable: true,
    });
});

afterEach(() => {
    if (original) {
        Object.defineProperty(globalThis, 'document', original);
    } else {
        Reflect.deleteProperty(globalThis, 'document');
    }
});

/*
 | The application name is deployment configuration (VITE_APP_NAME), so pinning
 | a literal here would make these tests fail on a rename rather than on a
 | regression. What this module actually decides is the separator and the
 | fallback, and those are what the assertions below hold to.
 */
const appName = formatTitle(null);

describe('formatTitle', () => {
    it('suffixes the application name', () => {
        expect(formatTitle('Vaults')).toBe(`Vaults — ${appName}`);
    });

    it('gives the bare application name when there is no page title', () => {
        expect(formatTitle(null)).toBe(appName);
        expect(formatTitle(undefined)).toBe(appName);
        expect(appName).not.toContain('—');
    });

    /*
     | An empty string takes the same branch as null rather than producing a
     | dangling separator. It is the state a page is in between mounting and its
     | payload opening, so it is the common case rather than an edge one.
     */
    it('treats an empty title as no title', () => {
        expect(formatTitle('')).toBe(appName);
    });
});

describe('useDocumentTitle', () => {
    it('sets the title immediately from a static string', () => {
        const scope = effectScope();
        scope.run(() => useDocumentTitle('Account'));

        expect(document.title).toBe(`Account — ${appName}`);

        scope.stop();
    });

    /*
     | The case the getter overload exists for: a vault's name is not known at
     | mount, only once the browser has opened the payload. Without reactivity
     | the tab would keep whatever the page rendered before the decrypt.
     */
    it('follows a title that only arrives after a decrypt', async () => {
        const name = ref<string | null>(null);
        const scope = effectScope();
        scope.run(() => useDocumentTitle(() => name.value));

        expect(document.title).toBe(appName);

        name.value = 'Infrastructure';
        await nextTick();

        expect(document.title).toBe(`Infrastructure — ${appName}`);
    });

    it('resets on dispose so a page does not lend the next one its name', async () => {
        const scope = effectScope();
        scope.run(() => useDocumentTitle('Infrastructure'));

        expect(document.title).toBe(`Infrastructure — ${appName}`);

        scope.stop();
        await nextTick();

        expect(document.title).toBe(appName);
    });

    /*
     | And the reason that reset matters more than tidiness: a vault name is
     | decrypted content. A stale one sitting above an unrelated page puts it in
     | the tab, the window title and any screen share, for a vault the user has
     | already navigated away from.
     */
    it('stops tracking a source it has been disposed of', async () => {
        const name = ref('Infrastructure');
        const scope = effectScope();
        scope.run(() => useDocumentTitle(() => name.value));

        scope.stop();
        await nextTick();

        name.value = 'Personal';
        await nextTick();

        expect(document.title).toBe(appName);
    });
});
