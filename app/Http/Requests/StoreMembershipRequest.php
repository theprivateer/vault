<?php

namespace App\Http\Requests;

use App\Enums\VaultRole;
use App\Rules\Envelope;
use App\Rules\Signature;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

/**
 * Granting somebody access to a vault.
 *
 * The interesting field is `grant_payload`, and it is the one place in this
 * application where the server reads structure out of something a client sent.
 * That is not a breach of the rule in `.ai/rules/app.md`: a grant is
 * authorisation metadata, not user content, it is signed rather than encrypted,
 * and it has to stay readable because the recipient's browser is served it back
 * to verify.
 *
 * What the server checks about it is written down in the controller, along with
 * the reason the check is worth nothing against a malicious server and is worth
 * having anyway.
 */
class StoreMembershipRequest extends FormRequest
{
    public function authorize(): bool
    {
        // The route's `can:share,vault` middleware decides this, before this
        // request is resolved. See .ai/rules/routes.md.
        return true;
    }

    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return [
            'membership_uuid' => ['required', 'uuid:7', Rule::unique('vault_memberships', 'uuid')],

            // The recipient, by public identifier. Never by internal id, and
            // never by an id the client could have guessed its way to.
            'user_uuid' => ['required', 'uuid', Rule::exists('users', 'uuid')],

            /*
             | An owner cannot be granted. A vault has exactly one owner — the
             | column on `vaults` — and a second administrator arriving through
             | the sharing path would leave two rows disagreeing about who that
             | is. Ownership transfer is its own operation.
             */
            'role' => ['required', Rule::enum(VaultRole::class)->except([VaultRole::Owner])],

            'wrapped_vault_key' => ['required', 'string', Envelope::sealed()],

            'grant_signature' => ['required', 'string', new Signature],

            'grant_payload' => ['required', 'string', 'max:2048', 'json'],
        ];
    }
}
