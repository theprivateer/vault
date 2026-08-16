<script setup lang="ts">
import { Link } from '@inertiajs/vue3';

import NoticePanel from '@/components/NoticePanel.vue';
import AuthLayout from '@/layouts/AuthLayout.vue';
import { useDocumentTitle } from '@/lib/title';

useDocumentTitle('No password reset');
</script>

<template>
    <AuthLayout title="There is no password reset" subtitle="This is a design decision, not an omission.">
        <div class="max-w-prose space-y-6 text-sm">
            <p>
                Your vault is encrypted with a key derived from your master password, in your browser. The
                server has never seen that password and holds no key that can decrypt anything you have
                stored.
            </p>

            <p>
                So there is nothing for a reset link to reset. If the server could put you back in touch with
                your data, so could anyone who compromised the server — which is exactly the situation this
                application is built to avoid.
            </p>

            <NoticePanel tone="accent" heading="if you still have your recovery kit">
                Use it to get back in and set a new password.
                <Link href="/recover" class="text-accent underline underline-offset-2">
                    Recover your account
                </Link>
            </NoticePanel>

            <NoticePanel heading="if you have lost both">
                Then the data is gone, permanently, and no one can retrieve it — including whoever runs this
                server. We would rather say that plainly than imply otherwise.
            </NoticePanel>

            <p class="text-2xs text-muted">
                <Link href="/login" class="underline underline-offset-2">back to sign in</Link>
            </p>
        </div>
    </AuthLayout>
</template>
