<?php

namespace App\Http\Requests;

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

    protected function vaultId(): int
    {
        return $this->routeLockbox()->vault_id;
    }
}
