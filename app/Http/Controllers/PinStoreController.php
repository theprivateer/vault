<?php

namespace App\Http\Controllers;

use App\Models\UserPinStore;
use App\Rules\Envelope;
use App\Support\Ciphertext;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Illuminate\Validation\ValidationException;

/**
 * Storing the encrypted record of whose keys a user has verified.
 *
 * The server's entire job here is to return the same bytes it was handed. It
 * cannot read the list — the blob is sealed under the User Key — which is what
 * stops it learning which substitutions would pass unnoticed, and what stops it
 * writing itself into the list as already trusted.
 *
 * It can still refuse to store a write, or serve an older copy. That is
 * unavoidable when it holds the bytes, and it is survivable: a missing pin
 * degrades to a verification prompt, never to a silent accept. The client is
 * built around that asymmetry (see `resources/js/stores/pins.ts`).
 */
class PinStoreController extends Controller
{
    /**
     * Replaces the pin store, refusing a write composed against a stale version.
     *
     * The same optimistic-concurrency shape as a secret edit, and for the same
     * reason: two devices that each verified somebody while the other was
     * offline must not silently discard one another's decision. Losing a
     * verification means the next share prompts again, which is merely annoying
     * — but the user would have been told it was recorded, and a security
     * decision that was reported as saved and was not is worse than annoying.
     */
    public function update(Request $request): JsonResponse
    {
        $request->validate([
            'pins_ct' => [
                'required',
                'string',
                Envelope::upTo(Config::integer('vault.max_payload_bytes')),
            ],
            'expected_version' => ['required', 'integer', 'min:0'],
        ]);

        $user = $this->currentUser($request);
        $expected = $request->integer('expected_version');
        $pinsCt = $request->string('pins_ct')->toString();

        /*
         | Queried rather than read off the relation. A relation loaded earlier
         | in the request lifecycle would be a snapshot, and the whole point of
         | the version check below is to act on what is in the table *now* —
         | deciding "there is no store yet" from a stale read is how two devices
         | end up both trying to create one.
         */
        $store = UserPinStore::query()->where('user_id', $user->getKey())->first();

        if ($store === null) {
            if ($expected !== 0) {
                throw $this->conflict();
            }

            $created = $user->pinStore()->create([
                'pins_ct' => $pinsCt,
                'version' => UserPinStore::INITIAL_VERSION,
            ]);

            return response()->json(['version' => $created->version]);
        }

        /*
         | Compared inside the `where`, never read and then checked. A
         | read-then-write leaves a window in which the other device commits,
         | and concurrent verification from two devices is the case being
         | defended.
         */
        $written = UserPinStore::query()
            ->whereKey($store->getKey())
            ->where('version', $expected)
            ->update([
                // Canonicalised by hand: a query-builder update bypasses the
                // model's casts, and the Ciphertext cast is where base64 is
                // normalised and the size cap applied.
                'pins_ct' => Ciphertext::fromBase64($pinsCt)->base64,
                'version' => $expected + 1,
                'updated_at' => now(),
            ]);

        if ($written === 0) {
            throw $this->conflict();
        }

        return response()->json(['version' => $expected + 1]);
    }

    private function conflict(): ValidationException
    {
        return ValidationException::withMessages([
            'expected_version' => 'Your list of verified identities was changed on another device. '
                .'Reload before verifying anyone else — nothing here has been lost.',
        ]);
    }
}
