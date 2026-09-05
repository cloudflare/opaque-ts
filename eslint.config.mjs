import eslintJS from '@eslint/js'
import eslintTS from 'typescript-eslint'
import pluginPrettier from 'eslint-plugin-prettier/recommended'
import pluginSecurity from 'eslint-plugin-security'
import pluginJest from 'eslint-plugin-jest'

export default eslintTS.config(
    eslintJS.configs.recommended,
    ...eslintTS.configs.strictTypeChecked,
    pluginJest.configs['flat/recommended'],
    pluginSecurity.configs.recommended,
    {
        ignores: [
            'jest.config.mjs',
            'eslint.config.mjs',
            'rollup.config.js',
            'coverage/*',
            'dist/*',
            'lib/*'
        ]
    },
    {
        languageOptions: {
            sourceType: 'module',
            parserOptions: {
                project: true,
                tsconfigRootDir: import.meta.dirname
            }
        },
        rules: {
            '@typescript-eslint/no-namespace': 'warn',
            '@typescript-eslint/no-unused-vars': [
                'error',
                {
                    args: 'all',
                    argsIgnorePattern: '^_',
                    caughtErrors: 'all',
                    varsIgnorePattern: '^_'
                }
            ],
            '@typescript-eslint/consistent-type-imports': 'error',
            '@typescript-eslint/consistent-type-exports': 'error',
            '@typescript-eslint/restrict-template-expressions': 'off'
        }
    },
    pluginPrettier
)
