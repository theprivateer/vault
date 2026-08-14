<?php

namespace App\Http\Requests;

/**
 * Re-encrypting a vault, lockbox or secret in place. The record itself is
 * resolved from the route and checked by a policy before this runs.
 */
class UpdateItemRequest extends ItemRequest
{
    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return $this->payloadRules();
    }
}
