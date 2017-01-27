<?php

namespace Vault\Files;

use Illuminate\Database\Eloquent\Model;
use Laracasts\Presenter\PresentableTrait;
use Privateer\Uuid\EloquentUuid;
use Vault\Lockboxes\Lockbox;

class File extends Model
{
    use EloquentUuid, PresentableTrait;

    protected $presenter = FilePresenter::class;

    public function lockbox()
    {
        return $this->belongsTo(Lockbox::class);
    }
}
