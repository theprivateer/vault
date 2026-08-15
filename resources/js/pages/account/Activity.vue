<script setup lang="ts">
/**
 * What this account has done, wherever it did it.
 *
 * The page that answers "am I the only one using this account". A recovery-kit
 * sign-in nobody remembers, a second factor turned off, a vault unlocked from
 * somewhere at four in the morning — all of it lands here, and a user who does
 * not recognise a line has learned something no other part of this application
 * could have told them.
 *
 * It includes events about vaults the user has since been removed from. Being
 * removed from a vault does not unmake what you did in it, and a history that
 * quietly shortened itself when access changed would be the wrong shape of
 * honest.
 */
import { Head } from '@inertiajs/vue3';

import ActivityFeed, { type ActivityEvent } from '@/components/ActivityFeed.vue';
import NoticePanel from '@/components/NoticePanel.vue';
import AppLayout from '@/layouts/AppLayout.vue';

defineProps<{ events: ActivityEvent[] }>();
</script>

<template>
    <AppLayout>
        <Head title="Your activity" />

        <h1 class="text-base font-medium">your activity</h1>

        <NoticePanel heading="read this for the lines you do not recognise" class="mt-4">
            A sign-in with a recovery kit, a second factor switched off, or a vault unlocked at an hour you
            were asleep are all worth a second look. Addresses are not stored — only a keyed hash of them — so
            this cannot tell you <em>where</em> from, and deliberately so.
        </NoticePanel>

        <div class="mt-6">
            <ActivityFeed :events="events" empty-message="Nothing recorded against this account yet." />
        </div>
    </AppLayout>
</template>
