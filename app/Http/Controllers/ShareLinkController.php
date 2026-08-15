<?php

namespace App\Http\Controllers;

use App\Enums\AuditAction;
use App\Enums\VaultRole;
use App\Http\Requests\StoreShareLinkRequest;
use App\Models\Lockbox;
use App\Models\Secret;
use App\Models\ShareLink;
use App\Models\User;
use App\Models\Vault;
use App\Support\AuditLog;
use App\Support\ShareToken;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\DB;
use Inertia\Inertia;
use Inertia\Response;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

/**
 * Creating, redeeming and revoking one-time share links.
 *
 * **The token never appears in a URL.** It lives in the fragment along with the
 * link key, and the recipient's browser sends it in a POST body. The
 * specification in docs/03 originally put it in the path — `/s/{token}` — and
 * that is the one part of this feature worth changing, because a path segment is
 * written to every access log in front of the application, in the clear, by
 * default. The security requirement that no log holds a token cannot be met by a
 * design that puts the token in the request line; it can be met by this one.
 *
 * It also fixes a caveat the specification listed as unavoidable: a chat client
 * unfurling the link fetches `GET /s` with no fragment, so a link preview cannot
 * consume the single view.
 */
class ShareLinkController extends Controller
{
    /**
     * The recipient's page. Serves no data at all.
     *
     * Deliberately outside both `auth` and `guest`: a link is for whoever holds
     * it, which may be a stranger or may be a signed-in colleague. The page ships
     * with nothing in it — the token is in a fragment this response never sees,
     * so there is nothing to render until the browser asks.
     */
    public function show(): Response
    {
        return Inertia::render('share/Open');
    }

    /**
     * Hands over the payload, once.
     *
     * The whole check-and-consume runs inside one transaction with the row
     * locked. Reading the view count and then updating it would let two
     * simultaneous requests both see "0 of 1" and both be served, which for a
     * one-time link is the entire failure mode.
     *
     * **The view is consumed before the response is sent**, so a response lost in
     * transit burns the view. That is the right direction to fail: the payload
     * left this server, and a link that quietly re-serves a secret because the
     * first delivery was not acknowledged is not one-time.
     */
    public function reveal(Request $request): JsonResponse
    {
        $request->validate([
            /*
             | The token itself, base64url, out of the fragment.
             |
             | The *token* travels and the *hash* is stored — not the other way
             | round. Having the browser send a hash would feel more careful and
             | would be strictly worse: the stored value would then be the thing
             | that redeems a link, and anyone who read the database could open
             | every outstanding share. Hashing on arrival is what keeps a stolen
             | dump insufficient.
             |
             | It is in a body rather than a path so that no access log holds it.
             */
            'token' => ['required', 'string', 'regex:/^[A-Za-z0-9_-]{43}$/'],
        ]);

        $token = $request->string('token')->toString();

        return DB::transaction(function () use ($token): JsonResponse {
            $link = ShareLink::query()
                ->where('token_hash', ShareToken::hash($token))
                ->lockForUpdate()
                ->first();

            /*
             | One response for every way of not being redeemable: missing,
             | expired, revoked, spent. Distinguishing them would tell a holder
             | of a guessed token that it once existed, and would tell a
             | recipient whether somebody else had already opened their link —
             | which is a fact about another person's behaviour.
             */
            if ($link === null || ! $link->isRedeemable()) {
                throw new NotFoundHttpException;
            }

            $link->forceFill(['view_count' => $link->view_count + 1])->save();

            AuditLog::record(AuditAction::ShareLinkViewed, $link, [
                'count' => $link->view_count,
                'max_views' => $link->max_views,
            ], actor: null);

            return response()->json([
                'payloadCt' => $link->payload_ct->base64,
                'payloadVersion' => $link->payload_version,
                'viewsRemaining' => $link->max_views - $link->view_count,
            ]);
        });
    }

    /**
     * Every link the current user is able to withdraw.
     *
     * **The list is defined by the policy rather than beside it.** A user can
     * revoke a link they created, or one created by anybody into a vault they
     * administer — so those are exactly the rows shown. Deriving the page from
     * the same rule as the ability means there is no second source of truth
     * about who sees what, and no way for an owner to hold a power over a link
     * they can never find.
     *
     * Rows that can no longer be opened are included until the hourly sweep
     * removes them. Seeing that a link was used, or expired unopened, is most of
     * why somebody opens this page — a list of only live links would answer a
     * narrower question than the one being asked.
     *
     * The secrets and vaults travel alongside because a link's *name* is inside
     * `payload_ct`: the server can say a link exists and when it expires, and
     * only the browser can say what it points at.
     */
    public function index(Request $request): Response
    {
        $user = $this->currentUser($request);

        $links = ShareLink::query()
            ->where(fn (Builder $query): Builder => $query
                ->where('created_by', $user->getKey())
                ->orWhereIn('secret_id', $this->secretsAdministeredBy($user)))
            ->with(['creator', 'secret.lockbox.vault'])
            ->orderByDesc('created_at')
            ->get();

        $secrets = $links
            ->map(fn (ShareLink $link): ?Secret => $link->secret)
            ->filter()
            ->unique('id');

        return Inertia::render('share/Links', [
            'links' => $links->map(fn (ShareLink $link): array => [
                ...$link->toClientArray(),
                // Whether this is one of theirs, or one they can withdraw
                // because they administer the vault it points into. The two read
                // very differently to somebody scanning the page.
                'mine' => $link->created_by === $user->getKey(),
            ]),
            'secrets' => $secrets->map(fn (Secret $secret): array => $secret->toClientArray())->values(),
            'vaults' => $this->vaultsFor($secrets, $user),
        ]);
    }

    /**
     * Creates a link for one secret.
     *
     * The payload arrives already sealed under a key this server will never
     * hold, so there is nothing here to get wrong cryptographically — which is
     * the design working rather than the code being simple.
     */
    public function store(StoreShareLinkRequest $request, Secret $secret): RedirectResponse
    {
        $link = ShareLink::query()->create([
            'uuid' => $request->string('uuid')->toString(),
            'token_hash' => $request->string('token_hash')->toString(),
            'payload_ct' => $request->string('payload_ct')->toString(),
            'payload_version' => $request->integer('payload_version'),
            'created_by' => $this->currentUser($request)->getKey(),
            'secret_id' => $secret->getKey(),
            'expires_at' => now()->addHours($request->integer('expires_in_hours')),
            'max_views' => $request->integer('max_views'),
            'created_at' => now(),
        ]);

        AuditLog::record(AuditAction::ShareLinkCreated, $link, [
            'max_views' => $link->max_views,
        ]);

        return back();
    }

    /**
     * Secrets in every vault this user administers, trashed rows included.
     *
     * Trashed ones matter: a link outlives the secret it came from, so an owner
     * tidying up a lockbox must not thereby lose the ability to withdraw links
     * pointing into it.
     *
     * As a subquery rather than a list of identifiers: this feeds a `whereIn`
     * on a table that may hold links for every vault in the deployment, and
     * three round trips to build an array the database is about to receive back
     * is work for nothing.
     *
     * @return Builder<Secret>
     */
    private function secretsAdministeredBy(User $user): Builder
    {
        $vaults = Vault::withTrashed()
            ->whereHas('memberships', fn (Builder $memberships): Builder => $memberships
                ->where('user_id', $user->getKey())
                ->where('role', VaultRole::Owner)
                ->whereNull('revoked_at'))
            ->select('id');

        $lockboxes = Lockbox::withTrashed()->whereIn('vault_id', $vaults)->select('id');

        return Secret::withTrashed()->whereIn('lockbox_id', $lockboxes)->select('id');
    }

    /**
     * The vault records the browser needs in order to name any of these.
     *
     * Only vaults the user still has a live membership of. A link they issued
     * into a vault they have since been removed from stays listed and stays
     * revocable — they created it — but nothing can put a name to it any more,
     * and the page says so rather than showing a blank.
     *
     * @param  Collection<int, Secret>  $secrets
     * @return list<array<string, mixed>>
     */
    private function vaultsFor(Collection $secrets, User $user): array
    {
        $records = [];

        foreach ($secrets->map(fn (Secret $secret): Vault => $secret->lockbox->vault)->unique('id') as $vault) {
            $membership = $vault->membershipFor($user);

            if ($membership !== null) {
                $records[] = $vault->toClientArray($membership);
            }
        }

        return $records;
    }

    /**
     * Ends a link early.
     *
     * Kept rather than deleted, so the row can still say a link existed and was
     * withdrawn. The sweep removes it later; until then the payload is
     * unreachable because `isRedeemable()` refuses it.
     */
    public function destroy(ShareLink $link): RedirectResponse
    {
        $link->forceFill(['revoked_at' => now()])->save();

        AuditLog::record(AuditAction::ShareLinkRevoked, $link, [
            'count' => $link->view_count,
        ]);

        return back();
    }
}
