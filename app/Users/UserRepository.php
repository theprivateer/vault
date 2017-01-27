<?php

namespace Vault\Users;


use Privateer\Uuid\UuidRepository;
use Vault\Vaults\Vault;

class UserRepository
{
    use UuidRepository;

    public function create($formData)
    {
        $user = User::create($formData);
        
        return $user;
    }

    public function update($user, $formData)
    {
        if(empty($formData['password']))
        {
            unset($formData['password']);
        } else
        {
            $formData['password'] = bcrypt($formData['password']);
        }

        $user->fill($formData);

        $user->save();

        return $user;
    }
}