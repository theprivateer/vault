<?php

namespace App\Http\Requests;

use App\Rules\Envelope;
use Illuminate\Validation\Rule;

/**
 * Creating a vault also creates the owner's membership, so this request carries
 * the sealed Vault Key alongside the payload. Both were produced in the browser
 * from keys the server has never held.
 */
class StoreVaultRequest extends ItemRequest
{
    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return [
            ...$this->newItemRules('vaults'),

            // The owner's own membership row, created in the same transaction.
            'membership_uuid' => ['required', 'uuid:7', Rule::unique('vault_memberships', 'uuid')],

            /*
             | The Vault Key sealed to the creator's X25519 public key. The
             | server stores it and can do nothing else with it: a sealed box
             | opens only with the recipient's private key, which is itself
             | encrypted under the User Key.
             */
            'wrapped_vault_key' => ['required', 'string', Envelope::sealed()],
        ];
    }
}
