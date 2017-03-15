@extends('layouts.app')

@section('content')
    @include('vaults.vault.partials.toolbar')

{!! Form::open(['role' => 'create-vault']) !!}
<div class="panel panel-default">
    <div class="panel-heading">
        <h3 class="panel-title">Create Vault</h3>
    </div>

    <div class="panel-body">
        <!-- Name Form Input -->
        <div class="form-group{{ $errors->has('name') ? ' has-error' : '' }}">
            {!! Form::label('name', 'Name:', ['class' => 'control-label']) !!}

            {!! Form::text('name', null, ['class' => 'form-control', 'required']) !!}

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
</div>

<div class="panel panel-default">
    <div class="panel-heading">
        <h3 class="panel-title">Security</h3>
    </div>

    <div class="panel-body">
        <p>For added security, all secrets in this vault will use strong client-side encryption before being sent to the server (where it will be encrypted again).</p>

        <!-- Password Form Input -->
        <div class="form-group">
            <label for="password" class="control-label">Master Password:</label>

            <input id="password" type="password" class="form-control" role="password">
        </div>

        <div class="form-group">
            <label for="password-confirmation" class="control-label">Confirm Master Password:</label>

            <input id="password-confirmation" type="password" class="form-control" role="password-confirmation">
        </div>
    </div>

    <div class="panel-footer">
        {!! Form::submit('Create Vault', ['class' => 'btn btn-primary']) !!}
    </div>

</div>

{!! Form::close() !!}
@endsection

@section('scripts')
    @parent

    <script>
        $('[role="create-vault"]').on('submit', function(e) {
            e.preventDefault();

            var theForm = this;

            // Password validation

            var password = $('[role="password"]').val();
            var password_conf = $('[role="password-confirmation"]').val();

            if(password != '')
            {
                if(password != password_conf)
                {
                    bootbox.alert('Your passwords don\'t match');
                } else
                {
                    secureTheForm(theForm, password);
                    theForm.submit();
                }

            } else
            {
                theForm.submit();
            }
        });

        function secureTheForm(theForm, password)
        {
            // Convenience UUID generator so that passkey can be stored immediately
            var uuid = generateUUID();

            setPasskey(password, uuid);

            $('<input type="hidden" />')
                .attr('name', 'uuid')
                .attr('value', uuid)
                .appendTo(theForm);

            // Now encrypt another random UUID for control purposes
            var encrypted = CryptoJS.AES.encrypt(generateUUID(), password);

            var str = encrypted.toString();

            $('<input type="hidden" />')
                .attr('name', 'control')
                .attr('value', str)
                .appendTo(theForm);
        }

        function setPasskey(passKey, uuid)
        {
            sessionStorage.setItem('{{ session()->getId() }}.' + uuid, passKey);
        }
    </script>
@endsection
