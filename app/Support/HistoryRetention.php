<?php

namespace App\Support;

use App\Models\Secret;
use App\Models\SecretVersion;
use App\Models\Vault;
use Illuminate\Support\Facades\DB;

/**
 * How much of a secret's past a vault keeps.
 *
 * The policy lives here rather than in the controller and the sweep separately,
 * because the two enforce different halves of it and a drift between them would
 * be invisible: history would be bounded by count on the write path and by a
 * subtly different count overnight, and nobody would notice until a version
 * somebody needed had gone early.
 *
 * **The two halves are enforced at different moments on purpose.** A count limit
 * is enforced the instant an edit archives a payload, because that is when the
 * count changes — a bound only a nightly job applied would let a scripted client
 * put a hundred thousand versions in a table between sweeps. An age limit is
 * enforced by the sweep, because nothing about a secret nobody has touched in a
 * year changes until the clock does.
 *
 * Neither is a security boundary against a member: anybody who could read the
 * versions has already read them, and deleting the rows does not unread
 * anything. What retention buys is that the *server's* copy stops existing, so
 * a database stolen next year holds fewer old passwords than it otherwise would.
 */
final class HistoryRetention
{
    /**
     * Trims one secret's history to the count its vault keeps.
     *
     * Returns how many rows went, so the caller can decide whether it is worth
     * saying anything. Nothing here writes to the audit log: this runs as part
     * of an edit that is already being recorded, and a second entry every time
     * an active secret passes its limit would bury the events somebody is
     * actually looking for.
     */
    public static function trimToCount(Secret $secret, Vault $vault): int
    {
        $keep = $vault->historyMaxVersions();

        $surviving = SecretVersion::query()
            ->where('secret_id', $secret->getKey())
            ->orderByDesc('version')
            ->limit($keep)
            ->pluck('id');

        /*
         | `whereNotIn` over the identifiers to keep rather than an offset,
         | because an offset would need the same ordering applied to a DELETE
         | and not every database allows one. The list is bounded by the
         | retention count, which is small by construction.
         |
         | Through the query builder rather than the model, as every other bulk
         | write to these tables is: a mass delete does not fire model events
         | either way, and the query builder is the one that returns a count
         | rather than a boolean.
         */
        return DB::table('secret_versions')
            ->where('secret_id', $secret->getKey())
            ->whereNotIn('id', $surviving)
            ->delete();
    }
}
