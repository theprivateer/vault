<?php

namespace Vault\Vaults;


use Privateer\Uuid\UuidRepository;
use Vault\Files\FileRepository;
use Vault\Lockboxes\LockboxRepository;
use Vault\Users\User;
use Vault\Users\UserRepository;

class VaultRepository
{
    use UuidRepository;

    public function create($formData, $user)
    {
        $vault = new Vault($formData);

        $this->save($vault, $user);

        (new LockboxRepository)->create([
            'vault'         => $vault->uuid,
            'name'          => 'Vault Control Lockbox',
            'description'   => 'A hidden lockbox used as a control mechanism for testing the vault passkey',
            'secrets'       => [
                    [
                        'key'       => 'control-key',
                        'value'     => 'control-value',
                    ]
            ]
        ], true);

        return $vault;
    }

    public function save(Vault $vault, $user)
    {
        if( ! is_object($user)) $user = (new UserRepository)->get($user);

        $vault->owner_id = $user->id;

        $vault->save();

        $user->vaults()->attach($vault);

        return $vault;
    }

    public function update($formData)
    {
        $vault = $this->get($formData['uuid']);

        $vault->fill($formData);

        $vault->save();

        return $vault;
    }

    public function getForUser($user)
    {
        if( ! is_object($user)) $user = User::where('uuid', $user)->firstOrFail();

        return $user->vaults()->orderBy('name')->get();
    }

    public function destroy($vault)
    {
        if( ! is_object($vault)) $vault = $this->get($vault);

        // Delete any files
        if($vault->files()->count())
        {
            $fileRepository = new FileRepository();

            foreach($vault->files as $file)
            {
                $fileRepository->destroy(['uuid' => $file->uuid]);
            }
        }

        return $vault->delete();
    }

}