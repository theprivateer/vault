<?php

namespace App\Http\Requests;

use App\Rules\Envelope;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Support\Facades\Config;
use Illuminate\Validation\Rule;

/**
 * Creating a one-time share link.
 *
 * Note which half of the credential each party sends. The **creator** posts
 * `token_hash`, so the server never holds a redeemable token even for the
 * duration of this request; the **recipient** later posts the token itself, and
 * the server hashes it to look the row up. Reversing either would put a working
 * credential somewhere it does not need to be.
 */
class StoreShareLinkRequest extends FormRequest
{
    public function authorize(): bool
    {
        // The route's `can:share,secret` decides this against a resolved record.
        return true;
    }

    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return [
            'uuid' => ['required', 'uuid:7', Rule::unique('share_links', 'uuid')],

            /*
             | Base64 of a 32-byte BLAKE2b digest: 44 characters including the
             | single `=` of padding. Sized exactly rather than loosely, because
             | this column is a unique index and anything else in it is a client
             | that has misunderstood the protocol.
             */
            'token_hash' => ['required', 'string', 'size:44', 'regex:/^[A-Za-z0-9+\/]{43}=$/'],

            /*
             | The secret's payload, re-sealed under the link key. Same envelope
             | rules as anything else — shape and size, never content.
             */
            'payload_ct' => [
                'required',
                'string',
                Envelope::upTo(Config::integer('vault.max_payload_bytes')),
            ],

            'payload_version' => [
                'required',
                'integer',
                Rule::in(Config::array('vault.payload_versions')),
            ],

            /*
             | An expiry is mandatory and bounded. A link that never expires is a
             | credential sitting in somebody's chat history for good, and the
             | one thing this feature must not become is a slow way to publish a
             | password.
             */
            'expires_in_hours' => [
                'required',
                'integer',
                'min:1',
                'max:'.Config::integer('vault.share_links.max_hours'),
            ],

            /*
             | More than one view is offered deliberately. It is less necessary
             | than it was — the token lives in the fragment, so a chat client's
             | link preview never sees it and cannot burn a view — but a
             | recipient who reloads, or opens the link on their phone after
             | their laptop, should not be locked out of something they were
             | given.
             */
            'max_views' => ['required', 'integer', 'min:1', 'max:'.Config::integer('vault.share_links.max_views')],
        ];
    }
}
