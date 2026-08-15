<script setup lang="ts">
/**
 * The audit log, rendered.
 *
 * Everything here came out of `audit_events` in the clear, and that is the
 * point: the log is metadata about *actions*, never content. A row says "added
 * a secret", never which one by name — the server has never known the name, and
 * the `AuditMetadata` allow-list is what keeps it that way.
 *
 * **Signed and unsigned entries are marked differently, and the difference is
 * real.** Most rows are the server's account of what it observed; a compromised
 * server could write any of them. The signed ones carry an Ed25519 signature
 * from the acting user's key, which the server does not hold, so it can neither
 * forge one nor strip one without breaking the chain. Presenting both as plain
 * history would flatten a distinction worth keeping.
 */
import { computed } from 'vue';

export interface ActivityEvent {
    seq: number;
    action: string;
    description: string;
    actor: string | null;
    subjectType: string | null;
    subjectUuid: string | null;
    metadata: Record<string, unknown>;
    signed: boolean;
    at: string;
}

const props = defineProps<{ events: ActivityEvent[]; emptyMessage: string }>();

/** Descending, as the server sent it — newest first is what anyone wants here. */
const rows = computed(() => props.events);

const formatter = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' });

function when(at: string): string {
    return formatter.format(new Date(at));
}

/**
 * The structural facts, rendered as `key value` pairs.
 *
 * Rendered generically rather than with a case per key, because the allow-list
 * in `AuditMetadata` is the thing that decides what may appear — a switch here
 * would be a second, quieter list that drifts from it.
 */
function details(metadata: Record<string, unknown>): string {
    return Object.entries(metadata)
        .map(([key, value]) => `${key.replace(/_/g, ' ')} ${String(value)}`)
        .join(' · ');
}
</script>

<template>
    <div v-if="rows.length" class="panel divide-y divide-line">
        <div v-for="event in rows" :key="event.seq" class="flex items-baseline gap-4 p-4">
            <!-- The sequence number, because a gap in it is the whole point. -->
            <span class="w-12 shrink-0 text-2xs text-faint tabular-nums">{{ event.seq }}</span>

            <div class="min-w-0 flex-1">
                <p class="text-sm">
                    <span class="text-ink">{{ event.actor ?? 'someone no longer here' }}</span>
                    {{ event.description }}
                </p>

                <p class="mt-1 text-2xs text-muted">
                    {{ when(event.at) }}
                    <template v-if="Object.keys(event.metadata).length">
                        · {{ details(event.metadata) }}
                    </template>
                </p>
            </div>

            <span
                v-if="event.signed"
                class="shrink-0 text-2xs text-accent"
                title="Signed in the browser with this account's key. The server cannot forge or remove it without breaking the chain."
            >
                signed
            </span>
        </div>
    </div>

    <p v-else class="text-sm text-muted">{{ emptyMessage }}</p>
</template>
