<?php

namespace App\Http\Requests;

use App\Rules\Envelope;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Support\Facades\Config;
use Illuminate\Validation\Rule;

/**
 * The shared validation for anything carrying an encrypted payload.
 *
 * Every rule below asks one of three questions: is this base64, is it the right
 * size, is its header one this build recognises. None of them looks at content,
 * and none of them could — the server holds no key for any of it.
 *
 * Getting this wrong in the permissive direction stores junk. Getting it wrong
 * in the *inquisitive* direction would be the beginning of the end of the whole
 * design, which is why the boundary is drawn once here rather than in each
 * subclass. See .ai/rules/app.md.
 */
abstract class ItemRequest extends FormRequest
{
    public function authorize(): bool
    {
        // Authorisation is a policy against a resolved record, and cannot be
        // decided from request input. The routes apply it.
        return true;
    }

    /**
     * The payload itself. Everything an update needs, and the core of a create.
     *
     * A fresh `wrapped_item_key` is expected on every write rather than reusing
     * the stored one: an edit generates a new Item Key, so nothing is ever
     * encrypted twice under the same one.
     *
     * @return array<string, mixed>
     */
    protected function payloadRules(): array
    {
        return [
            'payload_ct' => [
                'required',
                'string',
                Envelope::upTo(Config::integer('vault.max_payload_bytes')),
            ],

            // A 32-byte key in an envelope. Anything materially larger is not
            // a wrapped key and does not belong in this column.
            'wrapped_item_key' => ['required', 'string', Envelope::upTo(128)],

            'payload_version' => [
                'required',
                'integer',
                Rule::in(Config::array('vault.payload_versions')),
            ],
        ];
    }

    /**
     * The payload plus a client-generated identifier.
     *
     * The client generates it because the payload is sealed with associated
     * data bound to this identifier before the row exists. v7 keeps the index
     * well behaved; the uniqueness check stops a client reusing an identifier
     * to overwrite a record it should never have been able to name.
     *
     * Updates deliberately do not accept a `uuid` at all — it comes from the
     * route. Accepting both would admit a mismatch that only surfaced later, as
     * an integrity failure in someone's browser.
     *
     * @return array<string, mixed>
     */
    protected function newItemRules(string $table): array
    {
        return [
            'uuid' => ['required', 'uuid:7', Rule::unique($table, 'uuid')],
            ...$this->payloadRules(),
        ];
    }
}
