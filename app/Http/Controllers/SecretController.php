<?php

namespace App\Http\Controllers;

use App\Http\Requests\StoreSecretRequest;
use App\Http\Requests\UpdateSecretRequest;
use App\Models\Lockbox;
use App\Models\Secret;
use Illuminate\Http\RedirectResponse;

/**
 * Secrets.
 *
 * In 2017 this controller decrypted a secret's key and value on every read and
 * sent the plaintext to the browser. There is no equivalent here, and no way to
 * write one: `Ciphertext` has no decrypt method and the server holds no key.
 */
class SecretController extends Controller
{
    public function store(StoreSecretRequest $request, Lockbox $lockbox): RedirectResponse
    {

        $lockbox->secrets()->create([
            'uuid' => $request->string('uuid')->toString(),
            'payload_ct' => $request->string('payload_ct')->toString(),
            'wrapped_item_key' => $request->string('wrapped_item_key')->toString(),
            'payload_version' => $request->integer('payload_version'),
            'sort_order' => $request->integer('sort_order'),
            'linked_lockbox_id' => $this->linkedLockboxId($request, $lockbox),
        ]);

        return back();
    }

    public function update(UpdateSecretRequest $request, Secret $secret): RedirectResponse
    {

        $secret->update([
            'payload_ct' => $request->string('payload_ct')->toString(),
            'wrapped_item_key' => $request->string('wrapped_item_key')->toString(),
            'payload_version' => $request->integer('payload_version'),
            'linked_lockbox_id' => $this->linkedLockboxId($request, $secret->lockbox),
        ]);

        return back();
    }

    public function destroy(Secret $secret): RedirectResponse
    {

        $secret->delete();

        return back();
    }

    /**
     * Resolves the lockbox-as-a-value link, scoped to the same vault.
     *
     * The request rules already reject anything outside the vault. Re-scoping
     * the lookup means that even if that rule were ever loosened, the query
     * itself cannot reach across a vault boundary.
     */
    private function linkedLockboxId(StoreSecretRequest|UpdateSecretRequest $request, Lockbox $lockbox): ?int
    {
        $uuid = $request->string('linked_lockbox_uuid')->toString();

        if ($uuid === '') {
            return null;
        }

        $id = Lockbox::query()
            ->where('vault_id', $lockbox->vault_id)
            ->where('uuid', $uuid)
            ->value('id');

        return is_int($id) ? $id : null;
    }
}
