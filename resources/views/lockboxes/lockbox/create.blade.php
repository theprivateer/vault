@extends('layouts.app')

@section('content')
    @include('layouts.partials.lock')

    @include('lockboxes.partials.toolbar')

{!! Form::open(['role' => 'lockbox-form']) !!}
<div class="panel panel-default">
    <div class="panel-heading">
        <h3 class="panel-title">Create Lockbox</h3>
    </div>

    <div class="panel-body">
        {!! Form::hidden('vault', Auth::user()->currentVault->uuid) !!}

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
        <h3 class="panel-title">Add Secrets</h3>
    </div>

    <table class="table table-striped table-sortable" id="secrets-table">
        <thead>
        <tr>
            <th class="btn-column"></th>
            <th style="width: 30%;">Key/Label</th>
            <th>Value</th>
            <th class="btn-column"><i class="fa fa-eye-slash" data-toggle="tooltip" title="Obscure value when viewing"></i></th>
            <th class="btn-column"></th>
        </tr>
        </thead>

        <tbody>

        </tbody>
    </table>

    <div class="panel-body">
        <div class="form-group">
            <button class="btn btn-default" role="add-secret">Add A Secret</button>
        </div>

        <div class="form-group">
            <button class="btn btn-default" role="add-lockbox">Add A Link to Another Lockbox</button>
        </div>

    </div>
</div>

<div class="panel panel-default">
    <div class="panel-heading">
        <h3 class="panel-title">Notes</h3>
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
</div>

<div class="panel panel-default">
    <div class="panel-footer">
        {!! Form::submit('Create Lockbox', ['class' => 'btn btn-primary']) !!}
    </div>
</div>

{!! Form::close() !!}
@endsection

@section('scripts')
    @parent
    <script src="/js/vendor/handlebars.js"></script>
    <script src="/js/vendor/jquery.sortable.min.js"></script>
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

        var counter = 1;

        $('[role="add-secret"]').on('click', function(e) {
            e.preventDefault();

            var uuid = counter;

            var source   = $("#secret-row").html();
            var template = Handlebars.compile(source);
            var html    = template({uuid: uuid });

            $('#secrets-table tbody').append(html);

            doSorting();

            counter++;

        });

        $('[role="add-lockbox"]').on('click', function(e) {
            e.preventDefault();

            var uuid = counter;

            var source   = $("#lockbox-row").html();
            var template = Handlebars.compile(source);
            var html    = template({uuid: uuid });

            $('#secrets-table tbody').append(html);

            doSorting();

            counter++;

        });


        $(document).on('click', '[role="remove-secret"]', function(e)
        {
            e.preventDefault();

            var uuid = $(this).data('uuid');

            $('#' + uuid).remove();

            doSorting();

            // Append something to the form
            $('<input type="hidden" value="1" />')
                    .attr("name", 'field[' + uuid + '][destroy]')
                    .appendTo( $('#fields-form') );

        });

        $(function () {
            $('[data-toggle="tooltip"]').tooltip()
        });

        function initSorting()
        {
            if($('#secrets-table').length) {
                $('#secrets-table').sortable({
                    group: 'secrets',
                    containerSelector: 'table',
                    itemPath: '> tbody',
                    itemSelector: 'tr',
                    placeholder: '<tr class="placeholder"/>',
                    handle: 'td.sort-handle',
                    onDrop: function ($item, container, _super) {
                        $item.removeClass(container.group.options.draggedClass).removeAttr('style');
                        $('body').removeClass(container.group.options.bodyClass);

                        doSorting();

                        _super($item, container);
                    }
                });
            }
        }

        function doSorting()
        {
            var i = 0;
            $('#secrets-table tbody tr').each(function() {
                $('[role="sort-order"]', this).val(i);

                i++;
            });
        }

        initSorting();

        $('[role="lockbox-form"]').on('submit', function(e) {
            e.preventDefault();

            var theForm = this;

            var secrets = [];
            var i = 0;

            $('#secrets-table tbody tr').each(function(e) {

                secrets[i] = {};
                secrets[i].sort_order = $('[role="sort-order"]', this).val();
                secrets[i].key = encryptForCurrentVault($('[role="secret-key"]', this).val());

                if($('[role="secret-value"]', this).length > 0)
                {
                    secrets[i].value = encryptForCurrentVault($('[role="secret-value"]', this).val());
                }

                if($('[role="secret-lockbox-id"]', this).length > 0)
                {
                    secrets[i].linked_lockbox_id = $('[role="secret-lockbox-id"]', this).val();
                }

                secrets[i].paranoid = $('[role="secret-paranoid"]', this).is(':checked');

                i++;
            });

            $('<input type="hidden" />')
                .attr('name', 'secrets')
                .attr('value', JSON.stringify(secrets))
                .appendTo(theForm);

            theForm.submit();
        });
    </script>

    @include('lockboxes.partials.handlebars.secret-row')
    @include('lockboxes.partials.handlebars.lockbox-row')

@endsection
