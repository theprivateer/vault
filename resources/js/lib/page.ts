/**
 * The props every authenticated page carries, shared by
 * app/Http/Middleware/HandleInertiaRequests.php.
 */
import { usePage } from '@inertiajs/vue3';

import type { IdentityBundle, UnlockBundle } from '@/stores/session';

export interface SharedProps {
    auth: {
        user: { uuid: string; display_name: string; handle: string; email: string } | null;
        bundle: UnlockBundle | null;
        identity: (IdentityBundle & { ed25519PublicKey: string; selfSignature: string }) | null;
    };
    [key: string]: unknown;
}

export function useShared() {
    return usePage<SharedProps>();
}
