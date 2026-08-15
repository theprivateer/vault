<?php

namespace App\Http\Requests;

use App\Rules\Envelope;
use Illuminate\Support\Facades\Config;
use Illuminate\Validation\Rule;

class UpdateSecretRequest extends SecretRequest
{
    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return [
            ...$this->payloadRules(),
            ...$this->secretRules(),
            ...$this->archiveRules(),

            /*
             | The version the client had when it composed this write.
             |
             | Required rather than optional: a client that forgets to send it
             | would get last-write-wins silently, which is precisely the
             | failure this is here to prevent. The comparison happens in the
             | controller, as part of the update statement, because checking it
             | here would leave a window between the check and the write.
             */
            'expected_version' => ['required', 'integer', 'min:1'],
        ];
    }

    /**
     * The payload being replaced, re-sealed as its own archived version.
     *
     * **Required, not optional.** "Writes append rather than overwrite" is only
     * true if the server refuses a write that does not append; an optional
     * archive would mean a client with a bug quietly loses history and nobody
     * finds out until the version they needed is the one that was never kept.
     *
     * The consequence, stated because it is a real one: a secret whose stored
     * ciphertext no longer verifies cannot be edited. An edit has to archive
     * what it replaces, and a browser cannot re-seal a payload it was unable to
     * open. Deleting and re-adding is the way past it, and it has the better
     * property anyway — the unreadable row is kept rather than overwritten.
     *
     * @return array<string, mixed>
     */
    private function archiveRules(): array
    {
        return [
            /*
             | The archived payload is sealed against this identifier, so the
             | client mints it before encrypting. Unique for the same reason
             | every other client-generated identifier is: reusing one is how a
             | client would try to write over a record it should not be able to
             | name.
             */
            'version_uuid' => ['required', 'uuid:7', Rule::unique('secret_versions', 'uuid')],

            'version_payload_ct' => [
                'required',
                'string',
                Envelope::upTo(Config::integer('vault.max_payload_bytes')),
            ],

            'version_wrapped_item_key' => ['required', 'string', Envelope::upTo(128)],

            'version_payload_version' => [
                'required',
                'integer',
                Rule::in(Config::array('vault.payload_versions')),
            ],

            /*
             | Which archived version this write reached back for, when it is a
             | restore rather than an edit. It changes what the log says and
             | nothing about what is written — the server performs exactly the
             | same update either way, because a restore *is* a new version.
             | Never destructive, so there is nothing here to get wrong beyond
             | the label.
             */
            'restored_from' => ['nullable', 'integer', 'min:1'],
        ];
    }

    protected function vaultId(): int
    {
        return $this->routeLockbox()->vault_id;
    }
}
