<?php

namespace Vault\Secrets;


use Privateer\Uuid\UuidRepository;
use Vault\Lockboxes\Lockbox;

class SecretRepository
{
    use UuidRepository;

    public function create($lockbox, $formData)
    {
       return $this->update($lockbox, $formData);
    }

    public function update($lockbox, $formData)
    {
        if( ! is_object($lockbox)) $lockbox = Lockbox::where('uuid', $lockbox)->firstOrFail();

        foreach($formData as $key => $data)
        {

            if (is_numeric($key))
            {
                if( ! empty($data['key']))
                {
                    $secret = new Secret($data);

                    $lockbox->secrets()->save($secret);
                }
            } elseif(strpos($key, '_') !== 0) {

                $secret = Secret::whereUuid($key)->firstOrFail();


                if( isset($data['destroy']))
                {
                    $secret->delete();
                } else
                {
                    if(empty($data['paranoid'])) $data['paranoid'] = false;

                    $secret->fill($data);

                    $secret->save();
                }
            }
        }
    }
}