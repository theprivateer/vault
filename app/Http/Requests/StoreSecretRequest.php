<?php

namespace App\Http\Requests;

class StoreSecretRequest extends SecretRequest
{
    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return [
            ...$this->newItemRules('secrets'),
            ...$this->secretRules(),
        ];
    }

    protected function vaultId(): int
    {
        return $this->routeLockbox()->vault_id;
    }
}
