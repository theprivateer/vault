<?php

namespace Vault\Lockboxes;

use AlgoliaSearch\Laravel\AlgoliaEloquentTrait;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use Privateer\Uuid\EloquentUuid;
use Vault\Files\File;
use Vault\Secrets\Secret;
use Vault\Users\UserRepository;
use Vault\Vaults\Vault;

class Lockbox extends Model
{
    use EloquentUuid, AlgoliaEloquentTrait;

    public $indices = ['lockboxes'];

    public static $objectIdKey = 'uuid';

    protected $fillable = ['name', 'description', 'notes'];

    public function vault()
    {
        return $this->belongsTo(Vault::class);
    }

    public function secrets()
    {
        return $this->hasMany(Secret::class);
    }

    public function files()
    {
        return $this->hasMany(File::class);
    }

    public function canBeEditedBy($user)
    {
        if ( ! is_object($user)) $user = (new UserRepository)->get($user);

        $relationship = DB::table('user_vault')
            ->where('user_id', $user->id)
            ->where('vault_id', $this->vault_id)
            ->first();

        if( ! empty($relationship))
        {
            return ! ($relationship->read_only);
        }

        return false;

    }

    public function getAlgoliaRecord()
    {
        return [
            'uuid'          => $this->getAttribute('uuid'),
            'vault_id'      => $this->getAttribute('vault_id'),
            'display'       => $this->getAttribute('name') . ' [' . $this->vault->name . ']',
            'name'          => $this->getAttribute('name'),
            'description'   => $this->getAttribute('description'),
        ];
    }
}
