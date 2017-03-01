@extends('layouts.app')

@section('content')
    @include('layouts.partials.lock')

    @include('lockboxes.partials.toolbar')

    @php($_editable = $lockbox->canBeEditedBy(Auth::user()))

<div class="panel panel-default">
    <div class="panel-heading clearfix">
        <h3 class="panel-title pull-left @if($_editable) with-btn @endif">
            {{ $lockbox->name }}

            <button class="btn btn-sm btn-empty" role="clipboard-copy" data-clipboard-text="{{ route('lockbox.show', $lockbox->uuid) }}" data-toggle="tooltip" title="Copy lockbox URL to clipboard"><i class="fa fa-link"></i></button>
        </h3>

        @if($_editable)
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
        <h3 class="panel-title pull-left @if($_editable) with-btn @endif">Secrets</h3>

        @if($_editable)
            <a href="{{ route('secret.edit', $lockbox->uuid) }}" class="btn btn-default btn-sm pull-right">Edit</a>
        @endif
    </div>


    <table class="table table-striped table-panel">
        <tbody>
        @foreach($lockbox->secrets()->orderBy('sort_order')->get() as $secret)
            <tr>
                <td>
                    <span data-encrypted="{{ $secret->key }}"></span>&nbsp;
                </td>
                <td>
                    @if( empty($secret->linked_lockbox_id))
                    <span data-encrypted="{{ $secret->value }}" data-paranoid="{{ $secret->paranoid }}" data-clipboardable="true"></span>
                    @elseif($lockbox = $secret->linkedLockbox)
                    {!! link_to_route('lockbox.show', $lockbox->name, $lockbox->uuid, ['target' => '_blank']) !!}
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
        <h3 class="panel-title pull-left @if($_editable) with-btn @endif">Files</h3>

        @if($_editable)
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
