@extends('layouts.app')

@section('content')
    @include('layouts.partials.lock')

    @include('lockboxes.partials.toolbar')

    @include('lockboxes.partials.tabs', ['tab' => 'files'])

    <div class="panel panel-default has-tabs">

        @if($lockbox->files()->count())
        <table class="table table-striped table-panel">
            <tbody>
                @foreach($lockbox->files as $file)
                    <tr id="{{ $file->uuid }}">
                        <td>{{ $file->original_name }}</td>
                        <td>{{ byte_format($file->size) }}</td>
                        <td class="btn-column">
                            <a href="{!! $file->present()->download() !!}" class="btn btn-default btn-sm">Download</a>
                        </td>
                        <td class="btn-column">
                            {!! Form::open(['route' => 'file.destroy', 'method' => 'delete', 'role' => 'destroy-file']) !!}
                                {!! Form::hidden('uuid', $file->uuid) !!}
                                {!! Form::submit('Remove', ['class' => 'btn btn-default btn-sm']) !!}
                            {!! Form::close() !!}
                        </td>
                    </tr>
                @endforeach
            </tbody>
        </table>
    </div>

    <div class="panel panel-default">
        <div class="panel-heading">
            Upload Files
        </div>
        @endif
        <div class="panel-body">

            {!! Form::open(['route' => ['file.store', $lockbox->uuid], 'class' => 'dropzone', 'id' => 'fileUpload']) !!}
            {!! Form::hidden('lockbox', $lockbox->uuid) !!}

            <div class="fallback">
                <input name="file" type="file" multiple />
            </div>
            {!! Form::close() !!}
        </div>

        <div class="panel-footer" style="display: none;">
            <button class="btn btn-primary" role="start-upload">Upload Files</button>
        </div>
    </div>
@endsection

@section('head')
    @parent
    <link rel="stylesheet" href="/js/vendor/dropzone/dropzone.css">

@endsection

@section('scripts')
    @parent
    <script src="/js/vendor/dropzone/dropzone.js"></script>

    <script>
        Dropzone.autoDiscover = false;

        var myDropzone = new Dropzone('#fileUpload', {
            url: '{{ route('file.store', $lockbox->uuid) }}',
            addRemoveLinks: true,
            maxFilesize: {{ env('UPLOAD_LIMIT', 10) }},
            parallelUploads: 1,
            autoProcessQueue: false,
            init: function() {
                this.on("addedfile", function(file) { $('.panel-footer').show() });
                this.on('processing', function() {
                    this.options.autoProcessQueue = true;
                });
                this.on('queuecomplete', function() {
                    window.location.replace('{{ route('file.edit', $lockbox->uuid) }}');
                });
            }
        });

        $('[role="start-upload"]').on('click', function() {
            myDropzone.processQueue();
        });

        $(document).on('submit', '[role="destroy-file"]', function (e) {
            e.preventDefault();

            var theForm = this;

            bootbox.confirm('Are you sure you want to permanently delete this file?', function(result) {
                if(result)
                {
                    theForm.submit();
                }
            });
        });

    </script>

@endsection


