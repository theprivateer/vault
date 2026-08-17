<script setup lang="ts">
/**
 * The threat model, in the product (Phase 11, task 10; D10 and A3).
 *
 * A threat model that lives only in a repository is a document for people who
 * were already going to trust the thing. This page says the same three
 * uncomfortable sentences to the person actually typing a password in — that a
 * compromised server can serve malicious JavaScript, that nothing in the
 * browser can detect it, and that losing both credentials means the data is
 * gone.
 *
 * It is deliberately reachable without signing in, and deliberately not
 * marketing. Anything here that reads as reassurance rather than description is
 * a bug: the point of the page is the part that is bad news.
 */
import { Link } from '@inertiajs/vue3';

import NoticePanel from '@/components/NoticePanel.vue';
import AuthLayout from '@/layouts/AuthLayout.vue';
import { useDocumentTitle } from '@/lib/title';

useDocumentTitle('How this is secured');
</script>

<template>
    <AuthLayout
        title="How this is secured, and where it stops"
        subtitle="Including the parts that are not reassuring."
    >
        <div class="max-w-prose space-y-8 text-sm">
            <section class="space-y-3">
                <h2 class="text-2xs tracking-[0.08em] text-muted uppercase">what the server holds</h2>

                <p>
                    Everything you store is encrypted in your browser before it is sent. The server receives
                    ciphertext and stores it exactly as it arrives. It has no key that can open any of it, and
                    there is no code path anywhere on it that decrypts anything — not for search, not for
                    support, not for an administrator.
                </p>

                <p>
                    Your master password never leaves your browser. What the server stores is a slow hash of a
                    separate key derived alongside the one that does the decryption, so proving who you are
                    and being able to read your data are two different things.
                </p>
            </section>

            <section class="space-y-3">
                <h2 class="text-2xs tracking-[0.08em] text-muted uppercase">the limit of all of that</h2>

                <NoticePanel tone="accent" heading="a compromised server can serve you different code">
                    The encryption runs in JavaScript that this same server sends you. Whoever controls the
                    server can send a modified copy that captures your password as you type it, and your
                    browser will run it exactly as it runs the real one.
                </NoticePanel>

                <p>
                    Nothing on this page or in this application detects that. Not the strict content policy,
                    not the integrity hashes on the scripts, not the fact that the server holds no key — those
                    all constrain what a bug or an injected script can do, and none of them constrains the
                    server itself, because the server is what says what the rules are.
                </p>

                <p>
                    This is the honest ceiling on every browser-based encrypted application, this one
                    included. What it buys you is real and narrower than it sounds: a stolen database is
                    worthless on its own, a backup left somewhere is worthless on its own, and an operator
                    reading rows sees nothing. What it does not survive is the server being taken over while
                    you are still using it.
                </p>

                <p>
                    The two ways to reduce it are to run the server yourself, and to have somebody read the
                    code that runs in the browser. Both are the point of it being self-hosted and open.
                </p>
            </section>

            <section class="space-y-3">
                <h2 class="text-2xs tracking-[0.08em] text-muted uppercase">what is visible anyway</h2>

                <p>
                    The contents are encrypted; the shape is not. Somebody with the database can see how many
                    vaults and items you have, roughly how large each one is, when each was created and
                    changed, who shares which vault with whom, and when you last signed in.
                </p>

                <p>
                    Names, notes, usernames, passwords, card numbers, addresses, one-time-code seeds,
                    filenames and file contents are all encrypted, along with the kind of thing each item is.
                    Item sizes are padded into buckets so a short password and a long one are stored at the
                    same size; file sizes are not padded and are visible.
                </p>

                <p>
                    Because the padding is coarse, a large item is still visibly larger than a small one — so
                    while the server cannot read what kind of thing an item is, the space it takes up is a
                    weak hint at it. Weak is meant literally: most kinds of item share a size with several
                    others, and anything you write in the notes field swamps the difference entirely.
                </p>
            </section>

            <section class="space-y-3">
                <h2 class="text-2xs tracking-[0.08em] text-muted uppercase">what happens if you forget</h2>

                <NoticePanel heading="there is no reset, and no recovery of last resort">
                    If you lose your master password and your recovery kit, the data is permanently
                    unreadable. Not withheld pending identity checks — unreadable, by everyone, including
                    whoever runs this server.
                </NoticePanel>

                <p>
                    That is the same property as everything above, seen from the other side. A server that
                    could give you your data back after you forgot your password is a server that could give
                    it to somebody else.
                    <Link href="/forgot-password" class="text-accent underline underline-offset-2">
                        More on why there is no password reset
                    </Link>
                </p>

                <!--
                    The counterweight, and it belongs on this page rather than
                    only in a menu. "The data is gone" is only a defensible thing
                    to say to somebody who was always free to leave with a copy.
                -->
                <p>
                    Which is why you can take all of it out at any time, decrypted in your browser and written
                    to a file — either as plaintext, or as an archive under a passphrase of your choosing that
                    comes with a small offline program to open it. Neither needs this server to exist
                    afterwards.
                    <Link href="/account/export" class="text-accent underline underline-offset-2">
                        Export everything
                    </Link>
                </p>
            </section>

            <section class="space-y-3">
                <h2 class="text-2xs tracking-[0.08em] text-muted uppercase">
                    reporting something you have found
                </h2>

                <p>
                    Security reports are welcome, including ones about this page being wrong. The disclosure
                    policy is in
                    <span class="text-muted">SECURITY.md</span>
                    in the repository, and the full threat model — adversaries, accepted leakage, the
                    assumptions this all rests on — is in
                    <span class="text-muted">docs/02-threat-model.md</span>.
                </p>
            </section>

            <p class="text-2xs text-muted">
                <Link href="/vaults" class="underline underline-offset-2">back</Link>
            </p>
        </div>
    </AuthLayout>
</template>
