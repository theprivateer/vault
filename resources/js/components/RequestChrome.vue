<script setup lang="ts">
/**
 * The progress bar and the failure notice, replacing the two Inertia builds in.
 *
 * Not a preference. Both of Inertia's are assembled by assigning a string to
 * `innerHTML` — the progress bar does it once at startup, the error dialog does
 * it whenever a request comes back as HTML instead of a page — and the CSP this
 * application ships enforces Trusted Types with no default policy, so both of
 * those assignments throw. The progress bar's throw happens during app setup,
 * which is to say the application does not start.
 *
 * The alternatives were a default Trusted Types policy that returns its input,
 * which leaves the header in place and the protection gone, and an allow-list
 * of Inertia's exact template string, which breaks silently the first time
 * Inertia edits its own markup. Rendering both of them as components removes
 * the sink instead of permitting it: there is now no `innerHTML` assignment
 * anywhere in this application's runtime, ours or a dependency's.
 *
 * Mounted once into its own root by resources/js/app.ts rather than placed in a
 * layout, because it has to cover pages that use neither layout — the share
 * link view has no chrome at all — and because a navigation failure is
 * precisely the moment a layout may not be mounted.
 */
import { router } from '@inertiajs/vue3';
import { onBeforeUnmount, onMounted, ref } from 'vue';

/** null when idle; 0–100 while a visit is in flight. */
const progress = ref<number | null>(null);

const failure = ref<string | null>(null);

/**
 * Held so the bar does not flash on a fast visit, and so a stalled one does not
 * leave a frozen bar behind.
 */
let reveal: ReturnType<typeof setTimeout> | null = null;
let creep: ReturnType<typeof setInterval> | null = null;

const REVEAL_AFTER_MS = 250;

function stop(): void {
    if (reveal !== null) {
        clearTimeout(reveal);
        reveal = null;
    }

    if (creep !== null) {
        clearInterval(creep);
        creep = null;
    }
}

function start(): void {
    stop();

    reveal = setTimeout(() => {
        progress.value = 8;

        /*
         | The usual dishonest asymptote: nothing here knows how far along a
         | visit is, so the bar approaches the end without reaching it and the
         | response is what finishes it.
         */
        creep = setInterval(() => {
            const current = progress.value ?? 0;

            progress.value = current + (95 - current) * 0.1;
        }, 200);
    }, REVEAL_AFTER_MS);
}

function finish(): void {
    stop();

    if (progress.value === null) {
        return;
    }

    progress.value = 100;

    setTimeout(() => {
        progress.value = null;
    }, 200);
}

/**
 * What Inertia's dialog would have said, in one line and without an iframe.
 *
 * Deliberately vague about the cause. The body of a failed response may hold a
 * stack trace, and this application would rather say less than render whatever
 * arrived — see the note on error reporting in .ai/rules/pages.md.
 */
function describeStatus(status: number): string {
    if (status === 419) {
        return 'Your session expired. Reload the page and sign in again.';
    }

    if (status === 429) {
        return 'Too many requests. Wait a moment and try again.';
    }

    if (status >= 500) {
        return `The server could not complete that request (${status}).`;
    }

    return `That request was refused (${status}).`;
}

const detach: Array<() => void> = [];

onMounted(() => {
    detach.push(
        router.on('start', start),
        router.on('finish', finish),
        router.on('httpException', (event) => {
            // Suppresses Inertia's dialog. Without this the innerHTML in it
            // throws, and the user is told nothing at all.
            event.preventDefault();

            finish();
            failure.value = describeStatus(event.detail.response.status);
        }),
        router.on('networkError', (event) => {
            event.preventDefault();

            finish();
            failure.value = 'The request did not reach the server.';
        }),
        router.on('navigate', () => {
            failure.value = null;
        }),
    );
});

onBeforeUnmount(() => {
    stop();
    detach.forEach((off) => off());
});
</script>

<template>
    <div>
        <div
            v-if="progress !== null"
            class="fixed inset-x-0 top-0 z-50 h-0.5 bg-accent transition-[width] duration-200"
            :style="{ width: `${progress}%` }"
            role="progressbar"
            aria-label="loading"
        />

        <div
            v-if="failure"
            class="fixed inset-x-0 bottom-0 z-50 border-t border-l-2 border-t-line border-l-accent bg-sunken px-6 py-3"
            role="alert"
        >
            <div class="mx-auto flex max-w-5xl items-start justify-between gap-6">
                <p class="max-w-prose text-sm">{{ failure }}</p>

                <button
                    type="button"
                    class="text-2xs text-muted uppercase hover:text-ink"
                    @click="failure = null"
                >
                    dismiss
                </button>
            </div>
        </div>
    </div>
</template>
