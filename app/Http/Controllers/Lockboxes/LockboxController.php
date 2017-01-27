<?php

namespace Vault\Http\Controllers\Lockboxes;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Vault\Http\Requests\Lockbox\CreateRequest;
use Vault\Http\Requests\Lockbox\UpdateRequest;
use Vault\Lockboxes\LockboxRepository;
use Vault\Http\Controllers\Controller;

class LockboxController extends Controller
{

    /**
     * @var LockboxRepository
     */
    private $lockboxRepository;

    /**
     * lockboxController constructor.
     * @param LockboxRepository $lockboxRepository
     */
    public function __construct(LockboxRepository $lockboxRepository)
    {
        $this->lockboxRepository = $lockboxRepository;
    }

    public function index()
    {
        if( ! \Auth::user()->currentVault) return redirect()->route('vault.index');

        $lockboxes = $this->lockboxRepository->getPaginated(\Auth::user()->currentVault);

        return view('lockboxes.lockbox.index', compact('lockboxes'));
    }

    public function show($uuid)
    {
        $lockbox = $this->lockboxRepository->get($uuid);

        if( ! $this->lockboxAccessible($lockbox))
        {
            flash()->error('You do not have access to that lockbox');

            return redirect()->route('lockbox.index');
        }

        return view('lockboxes.lockbox.show', compact('lockbox'));
    }

    private function lockboxAccessible($lockbox)
    {
        if( ! is_object($lockbox)) $lockbox = $this->lockboxRepository->get($lockbox);

        if(in_array($lockbox->vault_id, Auth::user()->vaults->pluck('id')->all()))
        {
            Auth::user()->updateCurrentVault($lockbox->vault_id);

            return true;
        }

        return false;
    }

    public function create()
    {
        return view('lockboxes.lockbox.create');
    }

    public function store(CreateRequest $request)
    {
        $this->lockboxRepository->create($request->all());

        flash()->success('Lockbox created');

        return redirect()->route('lockbox.index');
    }

    public function edit($uuid)
    {
        $lockbox = $this->lockboxRepository->get($uuid);

        if( ! $this->lockboxAccessible($lockbox))
        {
            flash()->error('You do not have access to that lockbox');

            return redirect()->route('lockbox.index');
        }
        
        return view('lockboxes.lockbox.edit', compact('lockbox'));
    }

    public function update(UpdateRequest $request, $uuid)
    {
        if( ! $this->lockboxAccessible($request->get('uuid')))
        {
            flash()->error('You do not have access to that lockbox');

            return redirect()->route('lockbox.index');
        }


        $this->lockboxRepository->update($request->all());

        flash()->success('Lockbox updated');

        return redirect()->back();
    }

    public function move(Request $request, $uuid)
    {
        if( ! $this->lockboxAccessible($request->get('uuid')))
        {
            flash()->error('You do not have access to that lockbox');

            return redirect()->route('lockbox.index');
        }

        $this->lockboxRepository->move($request->all());

        flash()->success('Lockbox moved');

        return redirect()->route('lockbox.index');
    }

    public function destroy(Request $request)
    {
        if( ! $this->lockboxAccessible($request->get('uuid')))
        {
            flash()->error('You do not have access to that lockbox');

            return redirect()->route('lockbox.index');
        }

        $this->lockboxRepository->destroy($request->get('uuid'));

        flash()->success('Lockbox deleted');

        return redirect()->route('lockbox.index');
    }
}
