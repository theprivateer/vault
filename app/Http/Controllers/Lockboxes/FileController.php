<?php

namespace Vault\Http\Controllers\Lockboxes;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Storage;
use Vault\Files\File;
use Vault\Files\FileRepository;
use Vault\Http\Controllers\Controller;
use Vault\Lockboxes\LockboxRepository;

class FileController extends Controller
{

    /**
     * @var LockboxRepository
     */
    private $lockboxRepository;
    /**
     * @var FileRepository
     */
    private $fileRepository;

    /**
     * FileController constructor.
     * @param LockboxRepository $lockboxRepository
     * @param FileRepository $fileRepository
     */
    public function __construct(LockboxRepository $lockboxRepository, FileRepository $fileRepository)
    {
        $this->lockboxRepository = $lockboxRepository;
        $this->fileRepository = $fileRepository;
    }

    public function show($hash)
    {
        $details = json_decode( decrypt($hash) );

        try
        {
            $file = $this->fileRepository->get($details->uuid);

            if (Storage::exists($file->file_name)) {
                header("Cache-Control: must-revalidate, post-check=0, pre-check=0");
                header('Content-Description: File Transfer');
                header("Content-type: {$file->file_type}");
                header("Content-Disposition: attachment; filename={$file->original_name}");
                header("Expires: 0");
                header("Pragma: public");

                echo Storage::get($file->file_name);
            }
        } catch(\Exception $e)
        {

        }
    }

    public function edit($uuid)
    {
        $lockbox = $this->lockboxRepository->get($uuid);

        return view('lockboxes.file.edit', compact('lockbox'));
    }

    public function store(Request $request, $uuid)
    {
        if ($request->file('file')->isValid()) {

            $lockbox = $this->lockboxRepository->get($request->get('lockbox'));

            $upload = $request->file('file');

            $file = new File();

            $file->file_name = $upload->store('uploads/' . $lockbox->uuid);
            $file->original_name = $upload->getClientOriginalName();
            $file->file_type = $upload->getClientMimeType();
            $file->extension = $upload->getClientOriginalExtension();
            $file->size = $upload->getSize();

            $lockbox->files()->save($file);

            flash()->success('Upload complete');
        }
    }

    public function destroy(Request $request)
    {
        $this->fileRepository->destroy($request->all());

        flash()->success('File removed');

        return redirect()->back();
    }
}
