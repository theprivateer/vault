@extends('layouts.app')

@section('content')
    @include('lockboxes.partials.toolbar')


<div class="panel panel-default">
    <div class="panel-heading clearfix">
        <h3 class="panel-title pull-left">
            {{ $lockbox->name }}

            <button class="btn btn-sm btn-empty" role="clipboard-copy" data-clipboard-text="{{ route('lockbox.show', $lockbox->uuid) }}" data-toggle="tooltip" title="Copy lockbox URL to clipboard"><i class="fa fa-link"></i></button>
        </h3>

        @if($lockbox->canBeEditedBy(Auth::user()))
        <a href="{{ route('lockbox.edit', $lockbox->uuid) }}" class="btn btn-default btn-sm pull-right">Edit</a>
        @endif
    </div>

    @if( ! empty($lockbox->description))
        <div class="panel-body">
            {!! parse_markdown($lockbox->description) !!}
        </div>
    @endif
</div>

@if($lockbox->secrets()->count())
<div class="panel panel-default">
    <div class="panel-heading clearfix">
        <h3 class="panel-title pull-left">Secrets</h3>

        @if($lockbox->canBeEditedBy(Auth::user()))
            <a href="{{ route('secret.edit', $lockbox->uuid) }}" class="btn btn-default btn-sm pull-right">Edit</a>
        @endif
    </div>


    <table class="table table-striped table-panel">
        <tbody>
        @foreach($lockbox->secrets()->orderBy('sort_order')->get() as $secret)
            <tr>
                <td>
                    {{ $secret->key }}
                </td>
                <td>
                    {!! $secret->present()->value() !!}

                    @if( empty($secret->linked_lockbox_id))
                    <button class="btn btn-empty" role="clipboard-copy" data-clipboard-text="{{  $secret->value }}" data-toggle="tooltip" title="Copy to clipboard"><i class="fa fa-clipboard"></i></button>
                    @endif
                </td>
            </tr>
        @endforeach
        </tbody>
    </table>
</div>
@endif

@if($lockbox->files()->count())
<div class="panel panel-default">
    <div class="panel-heading clearfix">
        <h3 class="panel-title pull-left">Files</h3>

        @if($lockbox->canBeEditedBy(Auth::user()))
            <a href="{{ route('file.edit', $lockbox->uuid) }}" class="btn btn-default btn-sm pull-right">Edit</a>
        @endif
    </div>

    <table class="table table-striped table-panel">
        <tbody>
        @foreach($lockbox->files as $file)
            <tr>
                <td>{{ $file->original_name }}</td>
                <td>{{ byte_format($file->size) }}</td>
                <td class="btn-column">
                    <a href="{!! $file->present()->download() !!}" class="btn btn-default btn-sm">Download</a>
                </td>
            </tr>
        @endforeach
        </tbody>
    </table>
</div>
@endif

@if( ! empty($lockbox->notes))
<div class="panel panel-default">
    <div class="panel-body">
        {!! parse_markdown($lockbox->notes) !!}
    </div>
</div>
@endif

@endsection

@section('scripts')
    @parent
    <script src="/js/vendor/clipboard.min.js"></script>

    <script>
        $(function () {
            var clipboard = new Clipboard('[role="clipboard-copy"]');
            $('[data-toggle="tooltip"]').tooltip();
        });
    </script>
@endsection
