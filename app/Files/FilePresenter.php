<?php

namespace Vault\Files;


use Laracasts\Presenter\Presenter;

class FilePresenter extends Presenter
{
    public function download()
    {
        $array = [
            'uuid'  => $this->entity->uuid,
            'file_name' => $this->entity->file_name
        ];

        return route('file.show', encrypt(json_encode($array)));
    }
}