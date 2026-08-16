<?php

namespace App\Http\Requests;

use App\Rules\Base64Bytes;
use App\Rules\Envelope;
use App\Rules\Signature;
use Illuminate\Foundation\Http\FormRequest;

/**
 * Replacing a user's X25519/Ed25519 pair.
 *
 * The same shape as the identity half of registration, plus two things
 * registration has no need for: the sealed Vault Key for every membership,
 * re-sealed to the new public key, and a certificate signed by the key being
 * retired.
 *
 * **The membership set is required and must be complete.** That is enforced in
 * the controller rather than here, because completeness is a fact about the
 * database rather than about the request — but the consequence belongs next to
 * the rules: the old private key is discarded when this lands, so a membership
 * left out of the list is a vault its owner can never open again. No error, no
 * warning, nothing to recover from. It is the same failure mode as an incomplete
 * vault re-key, arriving from the other side of the key hierarchy.
 */
class RotateIdentityRequest extends FormRequest
{
    public function authorize(): bool
    {
        // The route's `auth` middleware decides this: an identity belongs to
        // exactly one account, and this rotates the caller's own.
        return true;
    }

    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return [
            'x25519_public_key' => ['required', 'string', Base64Bytes::exactly(32)],
            'ed25519_public_key' => ['required', 'string', Base64Bytes::exactly(32)],
            'x25519_private_key_ct' => ['required', 'string', Base64Bytes::between(50, 200)],
            'ed25519_private_key_ct' => ['required', 'string', Base64Bytes::between(50, 200)],
            'self_signature' => ['required', 'string', new Signature],
            'fingerprint' => ['required', 'string', Base64Bytes::exactly(32)],

            /*
             | The certificate. Stored byte-exact, so `json` here checks it is
             | readable and nothing more — the server never rebuilds it, exactly
             | as it never rebuilds a grant payload.
             */
            'rotation_payload' => ['required', 'string', 'max:1024', 'json'],
            'rotation_signature' => ['required', 'string', new Signature],

            /*
             | `present` rather than `required`: an account that belongs to no
             | vaults sends an empty array, and that is a complete set. Requiring
             | a non-empty list would make a new user's first rotation fail for
             | having nothing to carry across.
             */
            'memberships' => ['present', 'array', 'max:1000'],
            'memberships.*.uuid' => ['required', 'uuid'],
            'memberships.*.wrapped_vault_key' => ['required', 'string', Envelope::sealed()],
        ];
    }
}
