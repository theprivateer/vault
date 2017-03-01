@extends('layouts.app')

@section('content')

    @include('layouts.partials.lock', ['vault' => $vault])

    @include('vaults.vault.partials.toolbar')

<div class="panel panel-default">
    <div class="panel-heading clearfix">
        <h3 class="panel-title pull-left">Edit Vault</h3>

        @if(Auth::user()->current_vault_id != $vault->id)
        <a href="{{ route('vault.show', $vault->uuid) }}" class="btn btn-default btn-sm pull-right">Switch to Vault</a>
        @endif
    </div>
    {!! Form::model($vault) !!}

    {!! Form::hidden('uuid') !!}

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
        {!! Form::submit('Save Changes', ['class' => 'btn btn-primary']) !!}
    </div>
    {!! Form::close() !!}

</div>

<div class="panel panel-default">
    <div class="panel-heading">
        <h3 class="panel-title">Collaborators</h3>
    </div>

        <table class="table table-striped table-panel">
            <thead>
                <tr>
                    <th>Email</th>
                    <th>Read-only</th>
                    <th style="width: 1px;"></th>
                    <th style="width: 1px;"></th>
                </tr>
            </thead>
            <tbody>
                @foreach($vault->users->except(Auth::user()->id) as $user)
                <tr>
                    <td>{{ $user->email }}</td>
                    <td>
                        @if($user->pivot->read_only)
                            <i class="fa fa-check"></i>
                        @endif
                    </td>
                    <td>
                        {!! Form::open(['route' => ['vault.user.edit', $vault->uuid]]) !!}
                        {!! Form::hidden('vault', $vault->uuid) !!}
                        {!! Form::hidden('user', $user->uuid) !!}

                        @if($user->pivot->read_only)
                            {!! Form::hidden('read_only', 0) !!}
                            <button type="submit" class="btn btn-default btn-sm">Enable editing</button>
                        @else
                            {!! Form::hidden('read_only', 1) !!}
                            <button type="submit" class="btn btn-default btn-sm">Make Read-only</button>
                        @endif

                        {!! Form::close() !!}
                    </td>
                    <td>
                        @if( ! $user->owns($vault))
                        {!! Form::open(['route' => ['vault.user.destroy', $vault->uuid], 'method' => 'DELETE', 'role' => 'remove-collaborator']) !!}
                            {!! Form::hidden('vault', $vault->uuid) !!}
                            {!! Form::hidden('user', $user->uuid) !!}
                            <button type="submit" class="btn btn-default btn-sm">Remove</button>
                        {!! Form::close() !!}
                        @endif
                    </td>
                </tr>
                @endforeach
            </tbody>
        </table>

    {!! Form::open(['route' => ['vault.user.add', $vault->uuid]]) !!}
    <div class="panel-body">
        <p>Collaborators are not permitted to add additional collaborators or edit/delete the vault.</p>

        @if($vault->control)
            <p><strong>You will need to ensure that all collaborators know the master password for this vault.</strong></p>
        @endif

        <!-- Email Form Input -->
        <div class="form-group{{ $errors->has('email') ? ' has-error' : '' }}">
            {!! Form::label('email', 'Email Address:') !!}
            {!! Form::email('email', null, ['class' => 'form-control', 'placeholder' => 'john@example.com']) !!}

            <div class="checkbox">
                <label>
                    <input type="checkbox" name="read_only" value="1">

                    Read-only access - collaborator will not be able to add or edit lockboxes in this vault
                </label>
            </div>
            @if ($errors->has('email'))
                <span class="help-block">
                    <strong>{{ $errors->first('email') }}</strong>
                </span>
            @endif
        </div>
    </div>

    <div class="panel-footer">
        {!! Form::submit('Add Collaborator', ['class' => 'btn btn-primary']) !!}
    </div>
    {!! Form::close() !!}
</div>

<div class="panel panel-default">
    <div class="panel-heading">
        <h3 class="panel-title">Security</h3>
    </div>

    {!! Form::open(['role' => 'password-form']) !!}

    {!! Form::hidden('uuid', $vault->uuid) !!}
    {!! Form::hidden('name', $vault->name) !!}

    <div class="panel-body">
        <!-- Password Form Input -->
        <div class="form-group">
            <label for="password" class="control-label">Master Password:</label>

            <input id="password" type="password" class="form-control" role="password" required>
        </div>

        <div class="form-group">
            <label for="password-confirmation" class="control-label">Confirm Master Password:</label>

            <input id="password-confirmation" type="password" class="form-control" role="password-confirmation">
        </div>
    </div>

    <div class="panel-footer">
        {!! Form::submit('Update Master Password', ['class' => 'btn btn-primary']) !!}
    </div>
    {!! Form::close() !!}
</div>

<div class="panel panel-danger">
    <div class="panel-heading">
        <h3 class="panel-title">Danger Zone</h3>
    </div>

    <div class="panel-body">
        <p>Permanently delete this vault and all lockboxes/secrets within.  This action is instaneous and cannot be undone.</p>

    </div>

    <div class="panel-footer">
        {!! Form::model($vault, ['route' => 'vault.destroy', 'method' => 'DELETE', 'role' => 'destroy-vault']) !!}
        {!! Form::hidden('uuid') !!}
        {!! Form::submit('Delete Vault Now', ['class' => 'btn btn-danger']) !!}
        {!! Form::close() !!}
    </div>
</div>
@endsection

@section('scripts')
    @parent

    <script>
        $(document).on('submit', '[role="destroy-vault"]', function (e) {
            e.preventDefault();

            var theForm = this;

            bootbox.confirm('Are you sure you want to permanently delete this vault?', function(result) {
                if(result)
                {
                    theForm.submit();
                }
            });
        });

        $(document).on('submit', '[role="remove-collaborator"]', function (e) {
            e.preventDefault();

            var theForm = this;

            bootbox.confirm('Are you sure you want to remove this collaborator?', function(result) {
                if(result)
                {
                    theForm.submit();
                }
            });
        });

        $(document).on('submit', '[role="password-form"]', function (e) {
            e.preventDefault();

            var theForm = this;

            var p = $('[role="password"]', theForm).val();
            var password_conf = $('[role="password-confirmation"]', theForm).val();

            if(p == '')
            {
                bootbox.alert('Please enter a Master Password');
            } else if(p != password_conf)
            {
                bootbox.alert('Your passwords don\'t match');
            } else
            {
                bootbox.confirm('Are you sure you want to update the master password for this vault?', function(result) {
                    if(result)
                    {

                        // Get all of the secrets for this vault as a json string
                        $.get('{{ route('vault.secrets', $vault->uuid) }}', function(data, status){
                            var secrets = JSON.parse(data);

                            console.log(secrets);

                            var arrayLength = secrets.length;

                            // decrypt using current password, the encrypt using new password
                            for (var i = 0; i < arrayLength; i++) {
                                var key = decryptForCurrentVault(secrets[i].key);

                                secrets[i].key = CryptoJS.AES.encrypt(key, p).toString();


                                if(secrets[i].value)
                                {
                                    var value = decryptForCurrentVault(secrets[i].value);
                                    console.log(value);
                                    secrets[i].value = CryptoJS.AES.encrypt(value, p).toString();
                                }

                            }

                            $('<input type="hidden" />')
                                .attr('name', 'secrets')
                                .attr('value', JSON.stringify(secrets))
                                .appendTo(theForm);

                            // add a new control string to the payload
                            var encrypted = CryptoJS.AES.encrypt(generateUUID(), p);

                            var str = encrypted.toString();

                            $('<input type="hidden" />')
                                .attr('name', 'control')
                                .attr('value', str)
                                .appendTo(theForm);

                            // replace password in local session storage
                            setPasskey(p);

                            // submit form to server for persistence to database
                            theForm.submit();
                        });
                    }
                });
            }
        });
    </script>
@endsection
