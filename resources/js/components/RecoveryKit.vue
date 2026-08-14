<script setup lang="ts">
import { ref } from 'vue';

import NoticePanel from '@/components/NoticePanel.vue';

const props = defineProps<{
    code: string;
    email: string;
}>();

const emit = defineEmits<{ acknowledged: [] }>();

const understood = ref(false);
const copied = ref(false);

async function copy(): Promise<void> {
    await navigator.clipboard.writeText(props.code);
    copied.value = true;

    setTimeout(() => (copied.value = false), 3000);
}

function print(): void {
    window.print();
}
</script>

<template>
    <div class="space-y-6">
        <NoticePanel tone="accent" heading="write this down now">
            This is the only thing that can recover your account if you forget your password. It is shown
            once, on this screen, and is not stored anywhere on the server — we could not show it to you again
            if we wanted to.
        </NoticePanel>

        <div class="panel p-6 print:border-0 print:p-0">
            <p class="text-2xs tracking-[0.08em] text-muted uppercase">recovery kit &middot; {{ email }}</p>

            <p class="mt-4 font-mono text-lg break-all select-all">{{ code }}</p>

            <div class="mt-6 flex gap-2 print:hidden">
                <button type="button" class="btn" @click="copy">
                    {{ copied ? 'copied' : 'copy' }}
                </button>
                <button type="button" class="btn" @click="print">print</button>
            </div>
        </div>

        <div class="print:hidden">
            <label class="flex cursor-pointer items-start gap-3 text-sm">
                <input v-model="understood" type="checkbox" class="mt-1 accent-accent" />
                <span>
                    I have saved my recovery kit somewhere safe. I understand that if I lose both my password
                    and this kit, my data cannot be recovered by anyone — including whoever runs this server.
                </span>
            </label>

            <button
                type="button"
                class="btn btn-primary mt-6"
                :disabled="!understood"
                @click="emit('acknowledged')"
            >
                continue to my vault
            </button>
        </div>
    </div>
</template>
