@extends('layouts.app')

@section('content')

@include('layouts.partials.lock')

@include('lockboxes.partials.toolbar')

@forelse($lockboxes as $lockbox)
<div class="panel panel-default">
    <div class="panel-heading clearfix">
        <h3 class="panel-title pull-left with-btn">
            {!! link_to_route('lockbox.show', $lockbox->name, $lockbox->uuid) !!}
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
@empty
<div class="well text-center">
    <p class="lead">You have no lockboxes</p>
    @if(Auth::user()->canAddToCurrentVault())
    <a href="{{ route('lockbox.create') }}" class="btn btn-default btn-lg">Create Your First One</a>
    @endif
</div>
@endforelse

<div class="text-center">
{!! $lockboxes->links() !!}
</div>

@endsection
