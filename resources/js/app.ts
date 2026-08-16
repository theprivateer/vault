import '../css/app.css';

import { createInertiaApp } from '@inertiajs/vue3';
import { createApp, h } from 'vue';

import RequestChrome from '@/components/RequestChrome.vue';

const appName = import.meta.env.VITE_APP_NAME ?? 'Vault';

void createInertiaApp({
    title: (title) => (title ? `${title} — ${appName}` : appName),

    /*
     | Inertia's progress bar builds itself by assigning a template string to
     | `innerHTML` during setup. The CSP enforces Trusted Types with no default
     | policy (app/Http/Middleware/SecurityHeaders.php), so that assignment
     | throws and takes application startup with it.
     |
     | Turned off here and replaced by RequestChrome, which draws the same bar
     | out of a component and also stands in for Inertia's error dialog — built
     | the same way, from the body of a failed response, which is the one string
     | you would least like a browser to parse as markup.
     */
    progress: false,
});

/*
 | Mounted into its own root rather than into a layout: the share-link view has
 | no chrome at all, and a failed navigation is exactly the moment when the
 | layout you were relying on may not be mounted.
 */
const chrome = document.createElement('div');
document.body.appendChild(chrome);

createApp({ render: () => h(RequestChrome) }).mount(chrome);
