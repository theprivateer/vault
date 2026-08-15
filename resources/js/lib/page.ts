/**
 * The props every authenticated page carries, shared by
 * app/Http/Middleware/HandleInertiaRequests.php.
 */
import { usePage } from '@inertiajs/vue3';

import type { PinStoreRecord } from '@/stores/pins';
import type { IdentityBundle, UnlockBundle } from '@/stores/session';

export interface SharedProps {
    auth: {
        user: { uuid: string; display_name: string; handle: string; email: string } | null;
        bundle: UnlockBundle | null;
        identity: (IdentityBundle & { selfSignature: string }) | null;
        /** Encrypted; opened at unlock, alongside the identity it needs. */
        pins: PinStoreRecord | null;
    };
    [key: string]: unknown;
}

export function useShared() {
    return usePage<SharedProps>();
}
