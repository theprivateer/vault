<?php

namespace Vault\Users;

use Illuminate\Notifications\Notifiable;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Support\Facades\DB;
use Privateer\Uuid\EloquentUuid;
use Vault\Vaults\Vault;
use Vault\Vaults\VaultRepository;

class User extends Authenticatable
{
    use Notifiable, EloquentUuid;

    /**
     * The attributes that are mass assignable.
     *
     * @var array
     */
    protected $fillable = [
        'name', 'email', 'password',
    ];

    /**
     * The attributes that should be hidden for arrays.
     *
     * @var array
     */
    protected $hidden = [
        'password', 'remember_token',
    ];

    public function vaults()
    {
        return $this->belongsToMany(Vault::class)->withPivot('read_only');
    }

    public function writableVaults()
    {
        return $this->belongsToMany(Vault::class)->wherePivot('read_only', false);
    }

    public function currentVault()
    {
        return $this->belongsTo(Vault::class);
    }

    public function ownedVaults()
    {
        return $this->hasMany(Vault::class, 'owner_id');
    }

    public function owns($vault = null)
    {
        if ( is_null($vault))
        {
            $vault = $this->currentVault;

        } elseif ( ! is_object($vault))
        {
            $vault = (new VaultRepository)->get($vault);
        }

        return ($vault->owner_id == $this->id);
    }

    public function updateCurrentVault($vault)
    {
        $this->current_vault_id = $vault;
        $this->save();
    }

    public function canAddToCurrentVault()
    {
        $relationship = DB::table('user_vault')
            ->where('user_id', $this->id)
            ->where('vault_id', $this->current_vault_id)
            ->where('read_only', false)
            ->first();

        return ! empty($relationship);
    }
}
