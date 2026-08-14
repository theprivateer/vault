import js from '@eslint/js';
import ts from 'typescript-eslint';
import vue from 'eslint-plugin-vue';
import prettier from 'eslint-config-prettier';

export default ts.config(
    {
        ignores: ['public/**', 'vendor/**', 'node_modules/**', 'bootstrap/ssr/**', 'coverage/**'],
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
                            group: ['vue', '@inertiajs/*', '@/*', '../*', '!./*'],
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
        // Build config lives outside the tsconfig project, so type-aware rules
        // have no program to work from.
        files: ['*.config.{js,ts}'],
        extends: [ts.configs.disableTypeChecked],
    },
);
