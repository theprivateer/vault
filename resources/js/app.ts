import '../css/app.css';

import { createInertiaApp } from '@inertiajs/vue3';

const appName = import.meta.env.VITE_APP_NAME ?? 'Vault';

void createInertiaApp({
    title: (title) => (title ? `${title} — ${appName}` : appName),
});
