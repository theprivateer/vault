<?php

namespace Vault\Lockboxes;


use Privateer\Uuid\UuidRepository;
use Vault\Files\FileRepository;
use Vault\Secrets\Secret;
use Vault\Secrets\SecretRepository;
use Vault\Vaults\Vault;

class LockboxRepository
{
    use UuidRepository;

    protected $getWith = ['secrets'];

    public function getPaginated($vault)
    {
        if( ! is_object($vault)) $vault = Vault::where('uuid', $vault)->firstOrFail();

        return Lockbox::where('vault_id', $vault->id)
            ->orderBy('name')->paginate();
    }

    public function getListFor($user)
    {
        
        return Lockbox::with('vault')
            ->whereIn('vault_id', $user->vaults->pluck('id')->all())
            ->orderBy('name')->get();
    }

    public function getDropdownFor($user, $ignore = null)
    {
        $lockboxes = $this->getListFor($user);

        $array = [];

        foreach($lockboxes as $lockbox)
        {
            if($lockbox->id == $ignore) continue;
            
            $array[$lockbox->id] = $lockbox->name . ' [' . $lockbox->vault->name . ']';
        }

        return $array;
    }

    public function create($formData)
    {
        // Identify the Vault
        $vault = Vault::where('uuid', $formData['vault'])->firstOrFail();

        $lockbox = new Lockbox($formData);

        $vault->lockboxes()->save($lockbox);

        if(isset($formData['secrets'])) (new SecretRepository)->update($lockbox, $formData['secrets']);

        return $lockbox;
    }

    public function update($formData)
    {
        $lockbox = $this->get($formData['uuid']);

        $lockbox->fill($formData);

        $lockbox->save();

        if(isset($formData['secrets'])) (new SecretRepository)->update($lockbox, $formData['secrets']);

        return $lockbox;
    }

    public function move($formData)
    {
        $lockbox = $this->get($formData['uuid']);

        $vault = Vault::where('uuid', $formData['vault'])->firstOrFail();

        $vault->lockboxes()->save($lockbox);

        return;
    }

    public function destroy($uuid)
    {
        $lockbox = $this->get($uuid);

        // Remove all files
        if($lockbox->files()->count())
        {
            $fileRepository = new FileRepository();

            foreach($lockbox->files as $file)
            {
                $fileRepository->destroy(['uuid' => $file->uuid]);
            }
        }

        return $lockbox->delete();
    }


}