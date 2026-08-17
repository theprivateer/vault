import js from '@eslint/js';
import ts from 'typescript-eslint';
import vue from 'eslint-plugin-vue';
import prettier from 'eslint-config-prettier';

export default ts.config(
    {
        // `storage/**` holds the built crypto Worker, which lives outside
        // `public/` so the application can serve it with security headers.
        ignores: [
            'public/**',
            'storage/**',
            'vendor/**',
            'node_modules/**',
            'bootstrap/ssr/**',
            'coverage/**',
        ],
    },

    js.configs.recommended,
    ...ts.configs.recommendedTypeChecked,
    ...vue.configs['flat/recommended'],
    prettier,

    {
        languageOptions: {
            parserOptions: {
                projectService: true,
                tsconfigRootDir: import.meta.dirname,
                extraFileExtensions: ['.vue'],
                parser: ts.parser,
            },
        },
    },

    {
        files: ['resources/js/**/*.{ts,vue}'],
        rules: {
            /*
             | TypeScript already resolves every identifier, and no-undef has no
             | knowledge of DOM lib types — it flags `window`, `crypto` and
             | `setTimeout` as undefined. typescript-eslint recommends turning it
             | off for TS sources for exactly this reason.
             */
            'no-undef': 'off',

            // Type-based optional props carry `| undefined` rather than a
            // runtime default, which is what this rule wants to see.
            'vue/require-default-prop': 'off',

            /*
             | Nothing downstream of a decrypt may reach the console. Disabling
             | this rule inline is allowed, but it should be a conscious act with
             | a comment explaining why the logged value is not sensitive.
             | See docs/05-implementation-plan.md, cross-cutting practices.
             */
            'no-console': 'error',

            // Unhandled rejections in the crypto layer would surface as silent
            // failures rather than the loud errors SR3 requires.
            '@typescript-eslint/no-floating-promises': 'error',
            '@typescript-eslint/no-misused-promises': 'error',

            // v-html is the most direct route from a decrypted payload to XSS.
            'vue/no-v-html': 'error',
        },
    },

    {
        /*
         | The crypto core must stay framework-free and independently testable
         | (docs/05-implementation-plan.md, Phase 1). This rule is what enforces
         | "no app imports" rather than discipline.
         */
        files: ['resources/js/crypto/**/*.ts'],
        rules: {
            'no-restricted-imports': [
                'error',
                {
                    patterns: [
                        {
                            /*
                             | Blocks the framework and the app alias rather than
                             | relative depth: crypto/worker/ legitimately imports
                             | its siblings via '../', and anything reaching the
                             | application would go through '@/'.
                             */
                            group: ['vue', 'vue/*', '@inertiajs/*', 'pinia', '@/*'],
                            message:
                                'The crypto core must not depend on the application or its framework. Keep it standalone and independently testable.',
                        },
                    ],
                },
            ],
        },
    },

    {
        // Inertia page components are named after their route, not their markup,
        // so the multi-word convention does not apply to them.
        files: ['resources/js/pages/**/*.vue'],
        rules: {
            'vue/multi-word-component-names': 'off',
        },
    },

    {
        // Build config and benchmark scripts live outside the tsconfig project,
        // so type-aware rules have no program to work from.
        files: ['*.config.{js,ts}', 'benchmarks/**/*.{mjs,ts}'],
        extends: [ts.configs.disableTypeChecked],
        languageOptions: {
            globals: {
                console: 'readonly',
                performance: 'readonly',
                process: 'readonly',
            },
        },
        rules: {
            // A benchmark that cannot print its results is not a benchmark.
            'no-console': 'off',
        },
    },
);
