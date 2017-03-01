<?php

namespace Vault\Http\Controllers\Lockboxes;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Vault\Http\Controllers\Controller;
use Vault\Lockboxes\LockboxRepository;
use Vault\Secrets\SecretRepository;
use Vault\Vaults\VaultRepository;

class SecretController extends Controller
{

    /**
     * @var LockboxRepository
     */
    private $lockboxRepository;
    /**
     * @var SecretRepository
     */
    private $secretRepository;
    /**
     * @var VaultRepository
     */
    private $vaultRepository;

    /**
     * SecretController constructor.
     * @param LockboxRepository $lockboxRepository
     * @param SecretRepository $secretRepository
     * @param VaultRepository $vaultRepository
     */
    public function __construct(LockboxRepository $lockboxRepository, SecretRepository $secretRepository, VaultRepository $vaultRepository)
    {
        $this->lockboxRepository = $lockboxRepository;
        $this->secretRepository = $secretRepository;
        $this->vaultRepository = $vaultRepository;
    }

    public function edit($uuid)
    {
        $lockbox = $this->lockboxRepository->get($uuid);

        $linkableLockboxes = $this->lockboxRepository->getDropdownFor(Auth::user(), $lockbox->id);

        return view('lockboxes.secret.edit', compact('lockbox', 'linkableLockboxes'));
    }

    public function update(Request $request, $uuid)
    {
        $this->secretRepository->update($request->get('lockbox'), $request->get('secrets'), $request->get('delete-secrets'));

        flash()->success('Secrets updated');

        return redirect()->back();
    }

    public function index($uuid)
    {
        $vault = $this->vaultRepository->get($uuid);

        if( ! Auth::user()->owns($vault)) return;

        echo $vault->secrets;

    }
}
