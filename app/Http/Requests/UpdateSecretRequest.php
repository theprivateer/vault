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
        ];
    }

    protected function vaultId(): int
    {
        return $this->routeLockbox()->vault_id;
    }
}
