/**
 * The document title, set directly rather than through Inertia's `<Head>`.
 *
 * `<Head>` renders its elements by building an HTML string and assigning it to
 * `template.innerHTML`. The CSP enforces Trusted Types with no default policy
 * (app/Http/Middleware/SecurityHeaders.php), so that assignment throws — and it
 * would throw on every navigation, since every page sets a title.
 *
 * `document.title` is a plain string property and not a Trusted Types sink at
 * all, which is the point: this is not a workaround for the header, it is the
 * absence of the sink the header exists to guard. After this and the progress
 * bar in components/RequestChrome.vue, nothing in the application's runtime
 * assigns to `innerHTML` — asserted by the source sweep in security.test.ts.
 *
 * A page may pass a getter so that a title which is only known after a decrypt
 * — a vault's name, a lockbox's — updates when the payload opens.
 */
import { onScopeDispose, type MaybeRefOrGetter, toValue, watchEffect } from 'vue';

const appName = import.meta.env.VITE_APP_NAME ?? 'Vault';

/** The suffix rule, in one place, as the Inertia `title` callback used to be. */
export function formatTitle(title: string | null | undefined): string {
    return title ? `${title} — ${appName}` : appName;
}

export function useDocumentTitle(title: MaybeRefOrGetter<string | null | undefined>): void {
    watchEffect(() => {
        document.title = formatTitle(toValue(title));
    });

    /*
     | Reset on unmount so a page that leaves before the next one has decrypted
     | its name does not lend the tab its own — which, on a vault, would be the
     | previous vault's name sitting above an unrelated page.
     */
    onScopeDispose(() => {
        document.title = formatTitle(null);
    });
}
