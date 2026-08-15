<?php

namespace App\Http\Requests;

use App\Rules\Envelope;
use Illuminate\Foundation\Http\FormRequest;

/**
 * A whole vault's key material, re-wrapped, in one request.
 *
 * The shape is deliberately all-or-nothing. Every item key and every member's
 * sealed vault key arrives together, or the request is refused — there is no
 * partial form of this operation to submit, which is what makes a partial
 * application impossible rather than merely discouraged.
 *
 * That is the direct fix for the 2017 `vault:key` command, which walked the
 * vault re-encrypting as it went and left a half-rotated vault behind whenever
 * it stopped early.
 */
class RekeyVaultRequest extends FormRequest
{
    public function authorize(): bool
    {
        // `can:rekey,vault` on the route, before this request is resolved.
        return true;
    }

    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return [
            /*
             | Sent rather than inferred, so a client that has been looking at a
             | stale page cannot rotate on top of somebody else's rotation. The
             | server accepts it only at exactly current + 1.
             */
            'key_epoch' => ['required', 'integer', 'min:2'],

            // The vault's own payload key, re-wrapped under the new Vault Key.
            'vault_wrapped_item_key' => ['required', 'string', Envelope::upTo(128)],

            'items' => ['present', 'array', 'max:100000'],
            'items.*.uuid' => ['required', 'uuid'],
            'items.*.wrapped_item_key' => ['required', 'string', Envelope::upTo(128)],

            'memberships' => ['present', 'array', 'max:1000'],
            'memberships.*.uuid' => ['required', 'uuid'],
            'memberships.*.wrapped_vault_key' => ['required', 'string', Envelope::sealed()],
        ];
    }
}
