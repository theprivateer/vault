<?php

namespace App\Http\Controllers;

use App\Http\Requests\StoreLockboxRequest;
use App\Http\Requests\UpdateItemRequest;
use App\Models\Lockbox;
use App\Models\Secret;
use App\Models\Vault;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Inertia\Inertia;
use Inertia\Response;

/**
 * Lockboxes: a group of secrets inside a vault.
 *
 * The parent vault comes from the route and is authorised as a record. No
 * method here reads a vault identifier out of the request body — that is the
 * shape of an IDOR, and the way to not have one is to never accept the input.
 */
class LockboxController extends Controller
{
    public function show(Request $request, Lockbox $lockbox): Response
    {

        $secrets = $lockbox->secrets()
            ->with('linkedLockbox')
            ->orderBy('sort_order')
            ->orderBy('uuid')
            ->get()
            ->map(fn (Secret $secret): array => $secret->toClientArray());

        /*
         | The whole vault's lockboxes travel with the page so the browser can
         | render a link target's name, which it can only do by decrypting that
         | lockbox's payload. The server cannot resolve the name on its behalf.
         */
        $linkable = $lockbox->vault->lockboxes()
            ->orderBy('sort_order')
            ->orderBy('uuid')
            ->get()
            ->map(fn (Lockbox $sibling): array => $sibling->toClientArray());

        return Inertia::render('lockboxes/Show', [
            /*
             | The whole vault record, not just its identifier: the browser
             | cannot open anything here without first unsealing the Vault Key
             | from this user's membership row.
             */
            'vault' => $lockbox->vault->toClientArray($this->membershipFor($lockbox->vault, $request)),
            'lockbox' => $lockbox->toClientArray(),
            'secrets' => $secrets,
            'lockboxes' => $linkable,
        ]);
    }

    public function store(StoreLockboxRequest $request, Vault $vault): RedirectResponse
    {

        $vault->lockboxes()->create([
            'uuid' => $request->string('uuid')->toString(),
            'payload_ct' => $request->string('payload_ct')->toString(),
            'wrapped_item_key' => $request->string('wrapped_item_key')->toString(),
            'payload_version' => $request->integer('payload_version'),
            'sort_order' => $request->integer('sort_order'),
        ]);

        return back();
    }

    public function update(UpdateItemRequest $request, Lockbox $lockbox): RedirectResponse
    {

        $lockbox->update([
            'payload_ct' => $request->string('payload_ct')->toString(),
            'wrapped_item_key' => $request->string('wrapped_item_key')->toString(),
            'payload_version' => $request->integer('payload_version'),
        ]);

        return back();
    }

    public function destroy(Lockbox $lockbox): RedirectResponse
    {

        $lockbox->delete();

        return to_route('vaults.show', $lockbox->vault);
    }
}
