<?php

namespace Vault\Http\Controllers\Lockboxes;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Vault\Http\Controllers\Controller;
use Vault\Lockboxes\LockboxRepository;
use Vault\Secrets\SecretRepository;

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
     * SecretController constructor.
     * @param LockboxRepository $lockboxRepository
     * @param SecretRepository $secretRepository
     */
    public function __construct(LockboxRepository $lockboxRepository, SecretRepository $secretRepository)
    {
        $this->lockboxRepository = $lockboxRepository;
        $this->secretRepository = $secretRepository;
    }

    public function edit($uuid)
    {
        $lockbox = $this->lockboxRepository->get($uuid);

        $linkableLockboxes = $this->lockboxRepository->getDropdownFor(Auth::user(), $lockbox->id);

        return view('lockboxes.secret.edit', compact('lockbox', 'linkableLockboxes'));
    }

    public function update(Request $request, $uuid)
    {
        $this->secretRepository->update($request->get('lockbox'), $request->get('secrets'));

        flash()->success('Secrets updated');

        return redirect()->back();
    }
}
