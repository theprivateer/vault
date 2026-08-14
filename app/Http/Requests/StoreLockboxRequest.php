<?php

namespace App\Http\Requests;

/**
 * The vault comes from the route and is authorised before this runs. There is
 * no `vault_id` field, deliberately — a client that could name its own parent
 * could write into a vault it was never a member of.
 */
class StoreLockboxRequest extends ItemRequest
{
    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return [
            ...$this->newItemRules('lockboxes'),
            'sort_order' => ['sometimes', 'integer', 'min:0', 'max:65535'],
        ];
    }
}
