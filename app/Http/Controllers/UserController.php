<?php

namespace Vault\Http\Controllers;

use Illuminate\Http\Request;
use Vault\Http\Requests\User\UpdateRequest;
use Vault\Lockboxes\LockboxRepository;
use Vault\Users\UserRepository;

class UserController extends Controller
{

    /**
     * @var UserRepository
     */
    private $userRepository;

    /**
     * UserController constructor.
     * @param UserRepository $userRepository
     */
    public function __construct(UserRepository $userRepository)
    {
        $this->userRepository = $userRepository;
    }

    public function edit()
    {
        return view('user.edit');
    }

    public function update(UpdateRequest $request)
    {
        $user = $this->userRepository->get($request->get('uuid'));

        $this->userRepository->update($user, $request->all());

        flash()->success('Profile updated');

        return redirect()->back();
    }
}
