@extends('layouts.app')

@section('content')
    @include('layouts.partials.lock')

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
                <tr id="_{{ $secret->uuid }}">
                    <td class="sort-handle">
                        <i class="fa fa-sort"></i>
                        <input type="hidden" role="sort-order" value="{{ $secret->sort_order }}">
                        <input type="hidden" role="secret-uuid" value="{{ $secret->uuid }}">
                    </td>
                    <td>
                        <div class="form-group">
                            <input type="text" role="secret-key" class="form-control" placeholder="Key/Label" data-encrypted="{{ $secret->key }}" required>
                        </div>
                    </td>

                    @if( empty($secret->linked_lockbox_id))
                        <td>

                            <div class="form-group">
                                <input type="text" role="secret-value"  class="form-control" data-encrypted="{{ $secret->value }}" placeholder="Value">
                            </div>
                        </td>
                        <td>
                            <input type="checkbox" role="secret-paranoid" value="1" @if((boolean) $secret->paranoid) checked="checked" @endif>
                        </td>
                    @else
                        <td>
                            <div class="form-group">
                                <div class="input-group">
                                    <div class="input-group-addon"><i class="fa fa-lock"></i></div>
                                    {!! Form::select(null, $linkableLockboxes, $secret->linked_lockbox_id, ['class' => 'form-control', 'role' => 'secret-lockbox-id']) !!}
                                </div>
                            </div>
                        </td>
                        <td></td>
                    @endif
                    <td>
                        <button class="btn btn-default btn-block" role="remove-secret" data-uuid="_{{ $secret->uuid }}">Delete</button>
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
        var deleteSecrets = [];

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
            console.log(uuid);
            $('#' + uuid).remove();

            doSorting();

            deleteSecrets.push(uuid);

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

        $('#secrets-form').on('submit', function(e) {
            e.preventDefault();

            var theForm = this;

            var secrets = [];
            var i = 0;

            $('#secrets-table tbody tr').each(function(e) {

                secrets[i] = {};
                secrets[i].sort_order = $('[role="sort-order"]', this).val();
                secrets[i].key = encryptForCurrentVault($('[role="secret-key"]', this).val());

                if($('[role="secret-uuid"]', this).length > 0)
                {
                    secrets[i].uuid = $('[role="secret-uuid"]', this).val();
                }

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


            $('<input type="hidden" />')
                .attr('name', 'delete-secrets')
                .attr('value', JSON.stringify(deleteSecrets))
                .appendTo(theForm);

//            console.log( JSON.stringify(deleteSecrets));
            theForm.submit();
        });

    </script>

    @include('lockboxes.partials.handlebars.secret-row')
    @include('lockboxes.partials.handlebars.lockbox-row')
@endsection
