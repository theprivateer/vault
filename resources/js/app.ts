import '../css/app.css';

import { createInertiaApp } from '@inertiajs/vue3';
import { createApp, h } from 'vue';

import RequestChrome from '@/components/RequestChrome.vue';

void createInertiaApp({
    /*
     | **No `title` callback**, and its absence is load-bearing rather than an
     | omission. Inertia's head manager calls that callback with an empty string
     | to decide whether it owns a title; anything truthy comes back as
     | `<title data-inertia="">…</title>`, which the renderer then builds by
     | assigning to `template.innerHTML` — on app start and on every navigation.
     | With Trusted Types enforced that throws, which is what a real deployment
     | showed the first time a browser ran against the shipped header.
     |
     | The suffix rule lives in lib/title.ts, which sets `document.title`
     | directly. That is a plain string property and not a sink at all, so with
     | the callback gone the head manager collects nothing and never reaches the
     | renderer. Do not reintroduce this option, and do not use `<Head>`.
     */

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
