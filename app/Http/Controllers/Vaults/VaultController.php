<?php

namespace Vault\Http\Controllers\Vaults;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Vault\Http\Controllers\Controller;
use Vault\Http\Requests\Vault\CreateRequest;
use Vault\Http\Requests\Vault\DestroyRequest;
use Vault\Http\Requests\Vault\UpdateRequest;
use Vault\Vaults\VaultRepository;

class VaultController extends Controller
{

    /**
     * @var VaultRepository
     */
    private $vaultRepository;

    /**
     * VaultController constructor.
     * @param VaultRepository $vaultRepository
     */
    public function __construct(VaultRepository $vaultRepository)
    {
        $this->vaultRepository = $vaultRepository;
    }

    public function index()
    {
        $vaults = $this->vaultRepository->getForUser(Auth::user());

        return view('vaults.vault.index', compact('vaults'));
    }

    public function show($uuid)
    {
        $vault = $this->vaultRepository->get($uuid);

        Auth::user()->current_vault_id = $vault->id;
        Auth::user()->save();

        flash()->success('Switched to vault: ' . $vault->name);

        return redirect()->route('lockbox.index');
    }

    public function create()
    {
        return view('vaults.vault.create');
    }

    public function store(CreateRequest $request)
    {
        $vault = $this->vaultRepository->create($request->all(), Auth::user());

        flash()->success('Vault created');

        return redirect()->route('vault.index');
    }

    public function edit($uuid)
    {
        $vault = $this->vaultRepository->get($uuid);

        if( ! Auth::user()->owns($vault)) return redirect()->route('vault.index');

        return view('vaults.vault.edit', compact('vault'));
    }

    public function update(UpdateRequest $request, $uuid)
    {
        $this->vaultRepository->update($request->all());

        flash()->success('Vault updated');

        return redirect()->back();
    }

    public function destroy(DestroyRequest $request)
    {
        $vault = $this->vaultRepository->get($request->get('uuid'));

        if(Auth::user()->current_vault_id == $vault->id)
        {
            Auth::user()->current_vault_id = 0;
            Auth::user()->save();
        }

        $this->vaultRepository->destroy($vault);



        flash()->success('Vault destroyed');

        return redirect()->route('vault.index');
    }
}
