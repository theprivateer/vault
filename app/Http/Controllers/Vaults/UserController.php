<?php

namespace Vault\Http\Controllers\Vaults;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Vault\Http\Controllers\Controller;
use Vault\Notifications\CollaboratorAdded;
use Vault\Users\User;
use Vault\Users\UserRepository;
use Vault\Vaults\VaultRepository;

class UserController extends Controller
{
    public function store(Request $request, $uuid)
    {
        try
        {
            $user = User::where('email', $request->get('email'))->firstOrFail();

            // is that user already added to the vault?
            $vault = (new VaultRepository)->get($uuid);

            if( ! in_array($user->id, $vault->users->pluck('id')->all()))
            {
                $vault->users()->attach($user, ['read_only' => (boolean) $request->get('read_only')]);

                // Send a notification
                $user->notify(new CollaboratorAdded(Auth::user(), $vault));

                flash()->success('Collaborator added to vault');
            } else
            {
                flash()->error('User already on vault');
            }

        } catch( \Exception $e)
        {
            flash()->error('User not found');
        }

        return redirect()->back();
    }

    public function update(Request $request, $uuid)
    {
        $user = (new UserRepository)->get($request->get('user'));

        $vault = (new VaultRepository)->get($request->get('vault'));

        $user->vaults()->updateExistingPivot($vault->id, ['read_only' => $request->get('read_only')]);

        flash()->success('Collaborator updated');

        return redirect()->back();
    }

    public function destroy(Request $request, $uuid)
    {
        $user = (new UserRepository)->get($request->get('user'));

        $vault = (new VaultRepository)->get($request->get('vault'));

        $vault->users()->detach($user);

        if($user->id == Auth::user()->id)
        {
            flash()->success('Vault removed');
        } else
        {
            flash()->success('Collaborator removed');
        }

        return redirect()->back();
    }
}
