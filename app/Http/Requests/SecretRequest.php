<?php

namespace App\Http\Requests;

use App\Models\Lockbox;
use App\Models\Secret;
use Illuminate\Database\Query\Builder;
use Illuminate\Validation\Rule;
use RuntimeException;

/**
 * Shared rules for writing a secret, including the one field on these tables
 * that names another record: `linked_lockbox_uuid`.
 *
 * That is the 2017 lockbox-as-a-value feature. It is the reason the edge is
 * plaintext at all — the server has to see it to enforce that both ends live in
 * the same vault, which is enforced here rather than trusted from the client.
 */
abstract class SecretRequest extends ItemRequest
{
    /** The vault this secret belongs to, resolved from the route's record. */
    abstract protected function vaultId(): int;

    /**
     * @return array<string, mixed>
     */
    protected function secretRules(): array
    {
        return [
            'sort_order' => ['sometimes', 'integer', 'min:0', 'max:65535'],

            /*
             | Scoped to the same vault, so an identifier belonging to a vault
             | the user cannot see fails as "invalid" rather than linking. A
             | lockbox in another vault and one that does not exist are
             | indistinguishable in the response.
             */
            'linked_lockbox_uuid' => [
                'nullable',
                'uuid:7',
                Rule::exists('lockboxes', 'uuid')->where(
                    fn (Builder $query): Builder => $query
                        ->where('vault_id', $this->vaultId())
                        ->whereNull('deleted_at')
                ),
            ],
        ];
    }

    /** The lockbox bound to the current route, whichever parameter carries it. */
    protected function routeLockbox(): Lockbox
    {
        $lockbox = $this->route('lockbox');

        if ($lockbox instanceof Lockbox) {
            return $lockbox;
        }

        $secret = $this->route('secret');

        if ($secret instanceof Secret) {
            return $secret->lockbox;
        }

        throw new RuntimeException('A secret request must be routed through a lockbox or a secret.');
    }
}
