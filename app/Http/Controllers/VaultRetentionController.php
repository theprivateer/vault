<?php

namespace App\Http\Controllers;

use App\Enums\AuditAction;
use App\Http\Requests\UpdateRetentionRequest;
use App\Models\Lockbox;
use App\Models\Secret;
use App\Models\Vault;
use App\Support\AuditLog;
use App\Support\HistoryRetention;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Facades\DB;

/**
 * How long a vault keeps superseded payloads.
 *
 * Its own controller rather than another branch of `VaultController::update`,
 * because the two updates are different in kind: one re-encrypts a payload and
 * the server cannot see what changed, and this one writes two plaintext numbers
 * that decide when data is destroyed. They have different abilities, different
 * audit entries and different failure modes, and folding them together would
 * have meant one request that sometimes needs a Vault Key and sometimes does
 * not.
 */
class VaultRetentionController extends Controller
{
    /**
     * Applies the new policy, and applies it to what is already stored.
     *
     * **Shortening retention prunes immediately.** A setting that only takes
     * effect on the next edit or the next nightly sweep would tell somebody
     * their history was now five versions deep while twenty sat in the table —
     * and the person changing this setting is usually doing it *because*
     * something is in there they want gone. The number they see afterwards is
     * the number that is true.
     *
     * Only the count limit is applied here. The age limit is the sweep's, and
     * running it from a web request would mean an owner setting a policy waits
     * on a scan of every secret in the vault.
     */
    public function update(UpdateRetentionRequest $request, Vault $vault): RedirectResponse
    {
        DB::transaction(function () use ($request, $vault): void {
            $vault->forceFill([
                'history_max_versions' => $this->setting($request, 'max_versions'),
                'history_max_age_days' => $this->setting($request, 'max_age_days'),
            ])->save();

            $removed = 0;

            foreach ($this->secretsIn($vault) as $secret) {
                $removed += HistoryRetention::trimToCount($secret, $vault);
            }

            /*
             | The numbers and the damage in one entry. Recording the setting
             | without the count would leave a reader unable to tell a policy
             | tightened before anything accumulated from one that erased two
             | years of history the moment it was saved.
             */
            AuditLog::record(AuditAction::VaultRetentionChanged, $vault, [
                'max_versions' => $vault->historyMaxVersions(),
                'max_age_days' => $vault->historyMaxAgeDays(),
                'count' => $removed,
            ]);
        });

        return back();
    }

    /**
     * One setting, distinguishing "follow the default" from "keep none".
     *
     * `null` and `0` are both falsy and mean opposite things here — one defers
     * to `config/vault.php` and the other turns history off — so the empty
     * cases are named explicitly rather than left to a coalesce. An empty
     * string is included because that is what a cleared number input posts.
     */
    private function setting(UpdateRetentionRequest $request, string $key): ?int
    {
        $value = $request->input($key);

        return $value === null || $value === '' ? null : $request->integer($key);
    }

    /**
     * Every secret in the vault, trashed ones included.
     *
     * A soft-deleted secret is restorable for its grace period, so its history
     * is still history and the policy still governs it. Skipping trashed rows
     * would make "keep five versions" mean something different depending on
     * whether the secret happened to be in the bin.
     *
     * @return Collection<int, Secret>
     */
    private function secretsIn(Vault $vault): Collection
    {
        $lockboxes = Lockbox::withTrashed()
            ->where('vault_id', $vault->getKey())
            ->pluck('id');

        return Secret::withTrashed()
            ->whereIn('lockbox_id', $lockboxes)
            ->get(['id']);
    }
}
