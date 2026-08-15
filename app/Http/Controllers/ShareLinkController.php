<?php

namespace App\Http\Controllers;

use App\Enums\AuditAction;
use App\Http\Requests\StoreShareLinkRequest;
use App\Models\Secret;
use App\Models\ShareLink;
use App\Support\AuditLog;
use App\Support\ShareToken;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
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
