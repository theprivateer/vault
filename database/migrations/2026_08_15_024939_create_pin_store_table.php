<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * The trust-on-first-use pin store: whose keys this user has verified.
 *
 * This is the only durable record of a decision the server must not be able to
 * make or unmake. The whole point of fingerprint verification is to detect a
 * server that substitutes its own public key for someone else's, so a store the
 * server could read would tell it exactly which substitutions would go
 * unnoticed, and a store it could *write* would let it simply mark its own key
 * as already trusted.
 *
 * So it is one opaque blob encrypted under the User Key, and the server's entire
 * role is to hand back the same bytes it was given. It can still delete or roll
 * back the row — that is unavoidable — but the failure mode of a missing pin is
 * a verification prompt, which is safe. The failure mode of a *forged* pin is
 * silent interception, and that is what the encryption removes.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('user_pin_stores', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->unique()->constrained()->cascadeOnDelete();

            // { [userUuid]: fingerprintHex }, sealed under the User Key with the
            // `user.pins` AAD context bound to the owner's own UUID.
            $table->text('pins_ct');

            /*
             | Optimistic concurrency across devices. Two browsers that both
             | verified someone while offline must not silently discard one
             | another's decision: the second write is refused and the client
             | merges, exactly as a concurrent secret edit is handled.
             */
            $table->unsignedInteger('version')->default(1);

            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('user_pin_stores');
    }
};
