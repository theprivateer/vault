@extends('layouts.app')

@section('content')
    @include('vaults.vault.partials.toolbar')


    <div class="panel panel-default">
    <div class="panel-heading">
        <h3 class="panel-title">Create Vault</h3>
    </div>

    {!! Form::open() !!}
    <div class="panel-body">
        <!-- Name Form Input -->
        <div class="form-group{{ $errors->has('name') ? ' has-error' : '' }}">
            {!! Form::label('name', 'Name:', ['class' => 'control-label']) !!}

            {!! Form::text('name', null, ['class' => 'form-control']) !!}

            @if ($errors->has('name'))
                <span class="help-block">
                    <strong>{{ $errors->first('name') }}</strong>
                </span>
            @endif
        </div>

        <div class="form-group{{ $errors->has('description') ? ' has-error' : '' }}">
            {!! Form::label('description', 'Description:', ['class' => 'control-label']) !!}

            {!! Form::textarea('description', null, ['class' => 'form-control', 'rows' => 3]) !!}

            @if ($errors->has('description'))
                <span class="help-block">
                    <strong>{{ $errors->first('description') }}</strong>
                </span>
            @endif
        </div>
    </div>

    <div class="panel-footer">
        {!! Form::submit('Create Vault', ['class' => 'btn btn-primary']) !!}
    </div>
    {!! Form::close() !!}
</div>
@endsection
