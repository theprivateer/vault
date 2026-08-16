<?php

namespace App\Http\Requests;

use App\Rules\Base64Bytes;
use App\Rules\Envelope;
use App\Support\Ciphertext;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Support\Facades\Config;
use Illuminate\Validation\Rule;

/**
 * Re-sealing payloads at the current envelope version.
 *
 * **Not a re-key, and the difference is what shapes this request.** A rotation
 * has to be complete or the vault is stranded on two keys; a re-seal is
 * independent per row, because both envelope versions open and every row is
 * either one or the other. So this accepts a partial set on purpose: a large
 * vault can go a batch at a time, resume after a closed laptop, and stop half
 * way without leaving anything broken.
 *
 * `previous_digest` is a compare-and-swap. See the controller — without it a
 * tab that decrypted an hour ago could re-seal stale plaintext over a newer
 * edit, which would be data loss dressed up as maintenance.
 */
class ResealVaultRequest extends FormRequest
{
    public function authorize(): bool
    {
        // The route's `can:update,vault` decides this. See .ai/rules/routes.md.
        return true;
    }

    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return [
            /*
             | Bounded so one request cannot be arbitrarily large, and batching
             | is the client's job. A vault bigger than this simply takes more
             | requests, which a re-seal — unlike a re-key — is free to do.
             */
            'items' => ['required', 'array', 'min:1', 'max:200'],
            'items.*.uuid' => ['required', 'uuid'],

            // BLAKE2b-256 of the ciphertext this payload was decrypted from.
            'items.*.previous_digest' => ['required', 'string', Base64Bytes::exactly(32)],

            'items.*.payload_ct' => [
                'required',
                'string',
                Envelope::upTo(Config::integer('vault.max_payload_bytes')),
            ],
            'items.*.wrapped_item_key' => ['required', 'string', Envelope::upTo(Ciphertext::MAX_BYTES)],
            'items.*.payload_version' => [
                'required',
                'integer',
                Rule::in(Config::array('vault.payload_versions')),
            ],
        ];
    }
}
