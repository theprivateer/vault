@extends('layouts.app')

@section('content')
<h1 class="page-header text-center" style="margin-top: 0; margin-bottom: 12px;">
    Profile
</h1>

<div class="panel panel-default">
    {!! Form::model(Auth::user()) !!}

    {!! Form::hidden('uuid', null) !!}
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

            <!-- Email Form Input -->
            <div class="form-group{{ $errors->has('email') ? ' has-error' : '' }}">
                {!! Form::label('email', 'E-Mail Address:', ['class' => 'control-label']) !!}

                {!! Form::text('email', null, ['class' => 'form-control']) !!}

                @if ($errors->has('email'))
                <span class="help-block">
                    <strong>{{ $errors->first('email') }}</strong>
                </span>
                @endif
            </div>

            <!-- Password Form Input -->
            <div class="form-group{{ $errors->has('password') ? ' has-error' : '' }}">
                {!! Form::label('password', 'New Password:', ['class' => 'control-label']) !!}
                {!! Form::password('password', ['class' => 'form-control', 'placeholder' => 'Leave blank for no change']) !!}

                @if ($errors->has('password'))
                <span class="help-block">
                    <strong>{{ $errors->first('password') }}</strong>
                </span>
                @endif
            </div>

            <!-- Password Confirmation Form Input -->
            <div class="form-group">
                {!! Form::label('password_confirmation', 'Confirm New Password:', ['class' => 'control-label']) !!}
                {!! Form::password('password_confirmation', ['class' => 'form-control']) !!}
            </div>

    </div>

    <div class="panel-footer">
        {!! Form::submit('Save Changes', ['class' => 'btn btn-primary']) !!}
    </div>

    {!! Form::close() !!}
</div>

@endsection
