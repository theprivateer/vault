@extends('layouts.app')

@section('content')
    @include('lockboxes.partials.toolbar')

    @include('lockboxes.partials.tabs', ['tab' => 'secrets'])

    <div class="panel panel-default has-tabs">

        {!! Form::open(['id' => 'secrets-form']) !!}

        {!! Form::hidden('lockbox', $lockbox->uuid) !!}

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
            @foreach($lockbox->secrets()->orderBy('sort_order')->get() as $secret)
                <tr id="{{ $secret->uuid }}">
                    <td class="sort-handle">
                        <i class="fa fa-sort"></i>
                        {!! Form::hidden('secrets[' . $secret->uuid . '][sort_order]', $secret->sort_order, ['role' => 'sort-order']) !!}
                    </td>
                    <td>
                        <div class="form-group{{ $errors->has('secrets.' . $secret->uuid . 'key') ? ' has-error' : '' }}">
                            {!! Form::label('secrets[' . $secret->uuid . '][key]', 'Key:', ['class' => 'sr-only']) !!}

                            {!! Form::text('secrets[' . $secret->uuid . '][key]', $secret->key, ['class' => 'form-control']) !!}

                            @if ($errors->has('secrets.' . $secret->uuid . 'key'))
                                <span class="help-block">
                            <strong>{{ $errors->first('secrets.' . $secret->uuid . 'key') }}</strong>
                        </span>
                            @endif
                        </div>
                    </td>

                    @if( empty($secret->linked_lockbox_id))
                        <td>
                            <div class="form-group{{ $errors->has('secrets.' . $secret->uuid . 'value') ? ' has-error' : '' }}">
                                {!! Form::label('secrets[' . $secret->uuid . '][value]', 'Value:', ['class' => 'sr-only']) !!}

                                {!! Form::text('secrets[' . $secret->uuid . '][value]', $secret->value, ['class' => 'form-control']) !!}

                                @if ($errors->has('secrets.' . $secret->uuid . 'value'))
                                    <span class="help-block">
                            <strong>{{ $errors->first('secrets.' . $secret->uuid . 'value') }}</strong>
                        </span>
                                @endif
                            </div>
                        </td>
                        <td>
                            {!! Form::checkbox('secrets[' . $secret->uuid . '][paranoid]', 1, (boolean) $secret->paranoid) !!}
                        </td>
                    @else
                        <td>
                            <div class="form-group">
                                <div class="input-group">
                                    <div class="input-group-addon"><i class="fa fa-lock"></i></div>
                                    {!! Form::select('secrets[' . $secret->uuid . '][linked_lockbox_id]', $linkableLockboxes, $secret->linked_lockbox_id, ['class' => 'form-control']) !!}
                                </div>
                            </div>
                        </td>
                        <td></td>
                    @endif
                    <td>
                        <button class="btn btn-default btn-block" role="remove-secret" data-uuid="{{ $secret->uuid }}">Delete</button>
                    </td>
                </tr>
            @endforeach
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

        <div class="panel-footer">
            {!! Form::submit('Save Changes', ['class' => 'btn btn-primary']) !!}
        </div>
        {!! Form::close() !!}
    </div>
@endsection

@section('scripts')
    @parent
    <script src="/js/vendor/handlebars.js"></script>
    <script src="/js/vendor/jquery.sortable.min.js"></script>

    <script>
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
                    .attr("name", 'secrets[' + uuid + '][destroy]')
                    .appendTo( $('#secrets-form') );

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

    </script>

    @include('lockboxes.partials.handlebars.secret-row')
    @include('lockboxes.partials.handlebars.lockbox-row')
@endsection
