<?php

namespace App\Http\Requests\Auth;

use App\Rules\Base64Bytes;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

/**
 * Everything arriving here was produced in the browser. The server validates
 * shape and size only — it never parses a payload, and could not read one if it
 * tried.
 */
class RegisterRequest extends FormRequest
{
    public function authorize(): bool
    {
        // A valid, unexpired invitation is the authorisation. Checked in the
        // controller, where the token can be resolved to a record.
        return true;
    }

    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return [
            /*
             | Generated in the browser, because the User Key is wrapped with
             | associated data bound to this identifier before the row exists.
             | The server validates the version and uniqueness rather than
             | trusting it blindly.
             */
            'uuid' => ['required', 'uuid:7', Rule::unique('users', 'uuid')],

            'display_name' => ['required', 'string', 'max:100'],
            'handle' => [
                'required',
                'string',
                'min:2',
                'max:40',
                'regex:/^[a-z0-9][a-z0-9._-]*$/',
                Rule::unique('users', 'handle'),
            ],

            // Not secret, but must be the right size to be a salt at all.
            'kdf_salt' => ['required', 'string', Base64Bytes::exactly(16)],
            'kdf_params' => ['required', 'array'],
            'kdf_params.m' => ['required', 'integer', 'min:8192', 'max:1048576'],
            'kdf_params.t' => ['required', 'integer', 'min:2', 'max:10'],
            'kdf_params.p' => ['required', 'integer', 'min:1', 'max:4'],

            // All the server ever learns about the password.
            'auth_key' => ['required', 'string', Base64Bytes::exactly(32)],

            'wrapped_user_key' => ['required', 'string', Base64Bytes::between(50, 200)],
            'recovery_salt' => ['required', 'string', Base64Bytes::exactly(16)],
            'recovery_wrapped_user_key' => ['required', 'string', Base64Bytes::between(50, 200)],
            // Proves a recovery attempt without revealing the recovery code.
            'recovery_auth_key' => ['required', 'string', Base64Bytes::exactly(32)],

            'x25519_public_key' => ['required', 'string', Base64Bytes::exactly(32)],
            'ed25519_public_key' => ['required', 'string', Base64Bytes::exactly(32)],
            'x25519_private_key_ct' => ['required', 'string', Base64Bytes::between(50, 200)],
            'ed25519_private_key_ct' => ['required', 'string', Base64Bytes::between(50, 200)],
            'self_signature' => ['required', 'string', Base64Bytes::exactly(64)],
            'fingerprint' => ['required', 'string', Base64Bytes::exactly(32)],
        ];
    }

    /**
     * @return array<string, string>
     */
    public function messages(): array
    {
        return [
            'handle.regex' => 'The handle may only contain lowercase letters, numbers, dots, dashes and underscores.',
        ];
    }

    protected function prepareForValidation(): void
    {
        if (is_string($this->input('handle'))) {
            $this->merge(['handle' => strtolower(trim($this->input('handle')))]);
        }
    }
}
