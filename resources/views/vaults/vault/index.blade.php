@extends('layouts.app')

@section('content')
    @include('vaults.vault.partials.toolbar')

@forelse($vaults as $vault)
<div class="panel panel-default">
    <div class="panel-heading clearfix">
        <h3 class="panel-title pull-left">
            {{ $vault->name }}
        </h3>

        <div class="btn-group pull-right">

            @if(Auth::user()->current_vault_id != $vault->id)
                <a href="{{ route('vault.show', $vault->uuid) }}" class="btn btn-default btn-sm">Switch to Vault</a>
            @endif

            @if(Auth::user()->owns($vault))
                <a href="{{ route('vault.edit', $vault->uuid) }}" class="btn btn-default btn-sm">Manage</a>
            @else
                <a href="#" class="btn btn-default btn-sm" role="leave-vault" data-uuid="{{ $vault->uuid }}">Leave Vault</a>

                {!! Form::open(['route' => ['vault.user.destroy', $vault->uuid], 'method' => 'DELETE', 'id' => 'form-' . $vault->uuid]) !!}
                    {!! Form::hidden('vault', $vault->uuid) !!}
                    {!! Form::hidden('user', Auth::user()->uuid) !!}
                {!! Form::close() !!}
            @endif

        </div>
    </div>

    @if( ! empty($vault->description))
    <div class="panel-body">
        {!! parse_markdown($vault->description) !!}
    </div>
    @endif
</div>
@empty
<div class="well text-center">
    <p class="lead">You have no vaults</p>

    <a href="{{ route('vault.create') }}" class="btn btn-default btn-lg">Create Your First One</a>
</div>
@endforelse


@endsection

@section('scripts')
    @parent
    <script src="/js/vendor/bootbox.js"></script>

    <script>
        $(document).on('click', '[role="leave-vault"]', function (e) {
            e.preventDefault();

            var theForm = $('#form-' + $(this).data('uuid'));

            bootbox.confirm('Are you sure you want to leave this vault?', function(result) {
                if(result)
                {
                    theForm.submit();
                }
            });
        });
    </script>

@endsection