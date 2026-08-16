<script setup lang="ts">
/**
 * What has happened in one vault.
 *
 * The compensating control for everything the server cannot see. It cannot tell
 * you *what* was taken — it has never been able to read a secret — but it can
 * tell you that a session opened forty items in a minute at three in the
 * morning, and that is usually the question.
 *
 * Nothing on this page is decrypted, so it renders whether or not the vault is
 * unlocked. That is deliberate: the moment you most want to read an audit log is
 * the moment you are least sure the password is still yours.
 */
import { Link } from '@inertiajs/vue3';

import ActivityFeed, { type ActivityEvent } from '@/components/ActivityFeed.vue';
import NoticePanel from '@/components/NoticePanel.vue';
import AppLayout from '@/layouts/AppLayout.vue';
import { useDocumentTitle } from '@/lib/title';

defineProps<{ vault: { uuid: string }; events: ActivityEvent[] }>();

useDocumentTitle('Vault activity');
</script>

<template>
    <AppLayout>
        <Link :href="`/vaults/${vault.uuid}`" class="text-2xs text-muted hover:text-ink">
            &larr; back to vault
        </Link>

        <h1 class="mt-4 text-base font-medium">activity</h1>

        <NoticePanel heading="what this can and cannot tell you" class="mt-4">
            Every entry is chained to the one before it, so removing or changing one is detectable by
            <code>vault:audit-verify</code>. It is not proof against a server that rewrites the whole log —
            that would need only the same key material the log is written with. The entries marked
            <span class="text-accent">signed</span> are the exception: those were signed in a browser, with a
            key this server has never held.
        </NoticePanel>

        <div class="mt-6">
            <ActivityFeed :events="events" empty-message="Nothing has happened in this vault yet." />
        </div>
    </AppLayout>
</template>
