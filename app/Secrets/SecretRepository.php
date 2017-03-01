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

    public function update($lockbox = null, $json, $delete = null)
    {
        if( ! is_object($lockbox) && ! empty($lockbox)) $lockbox = Lockbox::where('uuid', $lockbox)->firstOrFail();

        $secrets = json_decode($json);

        foreach($secrets as $secret)
        {
            if(isset($secret->uuid))
            {
                $s = Secret::whereUuid($secret->uuid)->firstOrFail();

                if(empty($secret->paranoid)) $secret->paranoid = false;

                $s->fill(get_object_vars($secret));

                $s->save();

            } elseif( ! empty($lockbox))
            {
                $s = new Secret(get_object_vars($secret));

                $lockbox->secrets()->save($s);
            }
        }

        // Delete secrets where applicable
        if( ! empty($delete))
        {
            $delete = json_decode($delete);

            foreach($delete as $d)
            {
                try
                {
                    $s = Secret::whereUuid(str_replace('_', '', $d))->firstOrFail();

                    $s->delete();
                } catch(\Exception $e) { }

            }
        }
    }
}