<script id="secret-row" type="text/x-handlebars-template">
    <tr id="_{{ uuid }}">
        <td class="sort-handle">
            <i class="fa fa-sort"></i>
            <input type="hidden" role="sort-order">
        </td>
        <td>
            <div class="form-group">
                <input type="text" role="secret-key" class="form-control" placeholder="Key/Label" required>
            </div>
        </td>

        <td>
            <div class="form-group">
                <input type="text" role="secret-value"  class="form-control" placeholder="Value">
            </div>
        </td>

        <td>
            <input type="checkbox" role="secret-paranoid" value="1">
        </td>

        <td>
            <button class="btn btn-default btn-block" role="remove-secret" data-uuid="_{{ uuid }}">Delete</button>
        </td>
    </tr>
</script>