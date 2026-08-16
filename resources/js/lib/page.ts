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
        /**
         * Fingerprints this account has retired, oldest first, lowercase hex.
         *
         * A grant names the keys it was issued to, so without these every grant
         * made before a rotation would fail to verify and every shared vault
         * would render as a warning — over a change the user made themselves.
         */
        previousFingerprints: string[];
    };
    [key: string]: unknown;
}

export function useShared() {
    return usePage<SharedProps>();
}
