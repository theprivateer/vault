<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

/**
 * Handing a vault to somebody else.
 *
 * One field, and no key material — which is the whole shape of this operation.
 * Every other write in this application carries a ciphertext the browser
 * produced, because every other write changes what a key opens. Transfer changes
 * who is allowed to administer, and the recipient already holds the key, so
 * there is nothing for a client to seal and nothing for this request to validate
 * beyond naming a person.
 *
 * The conditions that make that person a *valid* recipient — a live membership,
 * at the current epoch, already accepted — are checked in the controller rather
 * than as validation rules. They are facts about the vault's state, and stating
 * them as `exists` rules against a table would answer "who is a member of this
 * vault" to anyone who could reach this endpoint.
 */
class TransferOwnershipRequest extends FormRequest
{
    public function authorize(): bool
    {
        // The route's `can:transfer,vault` middleware decides this, before this
        // request is resolved. See .ai/rules/routes.md.
        return true;
    }

    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return [
            'user_uuid' => ['required', 'uuid', Rule::exists('users', 'uuid')],
        ];
    }
}
