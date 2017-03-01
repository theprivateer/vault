@extends('layouts.app')

@section('content')
    @include('layouts.partials.lock')

    @include('lockboxes.partials.toolbar')

    {!! Form::model($lockbox, ['id' => 'lockbox-form']) !!}

    {!! Form::hidden('uuid',null) !!}

    @include('lockboxes.partials.tabs', ['tab' => 'edit'])

    <div class="panel panel-default has-tabs">

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
</div>

<div class="panel panel-default">
    <div class="panel-heading">
        <h3 class="panel-title">Update Notes</h3>
    </div>

    <div class="panel-body">
        <div class="form-group{{ $errors->has('notes') ? ' has-error' : '' }}">
            {!! Form::label('notes', 'notes:', ['class' => 'sr-only']) !!}

            {!! Form::textarea('notes', null, ['class' => 'form-control', 'placeholder' => 'Instructions, notes, extra information...', 'role' => 'editor']) !!}

            @if ($errors->has('notes'))
                <span class="help-block">
                <strong>{{ $errors->first('notes') }}</strong>
            </span>
            @endif
        </div>
    </div>

    <div class="panel-footer">
        {!! Form::submit('Save Changes', ['class' => 'btn btn-primary']) !!}
    </div>
</div>
{!! Form::close() !!}

<div class="panel panel-danger">
    <div class="panel-heading">
        <h3 class="panel-title">Danger Zone</h3>
    </div>

    <div class="panel-body">
        <p>Permanently delete this lockbox from the vault.  This action is instaneous and cannot be undone.</p>
    </div>

    <div class="panel-footer">
        {!! Form::model($lockbox, ['route' => 'lockbox.destroy', 'method' => 'DELETE', 'role' => 'destroy-lockbox']) !!}
        {!! Form::hidden('uuid') !!}
        {!! Form::submit('Delete Lockbox Now', ['class' => 'btn btn-danger']) !!}
        {!! Form::close() !!}
    </div>
</div>
@endsection


@section('scripts')
    @parent
    <script src="/js/vendor/tinymce/tinymce.min.js"></script>

    <script>
        function tinymceInit()
        {
            tinymce.init({
                selector: 'textarea[role="editor"]',
                menubar : false,
                content_css : '/js/vendor/tinymce/editor.css',
                statusbar : false,
                plugins: "link code paste",
                toolbar: "bold italic styleselect | bullist numlist | link code",
                valid_elements : '+*[*]',
                convert_urls: false,
                style_formats: [
                    {title: "Header 1", format: "h1"},
                    {title: "Header 2", format: "h2"},
                    {title: "Header 3", format: "h3"},
                    {title: "Header 4", format: "h4"},
                    {title: "Header 5", format: "h5"},
                    {title: "Header 6", format: "h6"},
                    {title: "Blockquote", format: "blockquote"}
                ]
            });
        }

        tinymceInit();


        $(document).on('submit', '[role="destroy-lockbox"]', function (e) {
            e.preventDefault();

            var theForm = this;

            bootbox.confirm('Are you sure you want to permanently delete this lockbox?', function(result) {
                if(result)
                {
                    theForm.submit();
                }
            });
        });
    </script>

@endsection
