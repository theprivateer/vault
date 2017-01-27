<?php

namespace Vault\Files;


use Illuminate\Support\Facades\Storage;
use Privateer\Uuid\UuidRepository;

class FileRepository
{
    use UuidRepository;

    public function destroy($formData)
    {
        $file = $this->get($formData['uuid']);

        // remove the file from filesystem
        Storage::delete($file->file_name);

        // then delete
        $file->delete();

        return;
    }
}