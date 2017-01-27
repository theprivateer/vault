<script id="secret-row" type="text/x-handlebars-template">
    <tr id="_{{ uuid }}">
        <td class="sort-handle">
            <i class="fa fa-sort"></i>
            <input type="hidden" name="secrets[{{ uuid }}][sort_order]" role="sort-order">
        </td>
        <td>
            <div class="form-group">
                <input type="text" name="secrets[{{ uuid }}][key]" class="form-control" placeholder="Key/Label" required>
            </div>
        </td>

        <td>
            <div class="form-group">
                <input type="text" name="secrets[{{ uuid }}][value]" class="form-control" placeholder="Value">
            </div>
        </td>

        <td>
            <input type="checkbox" name="secrets[{{ uuid }}][paranoid]" value="1">
        </td>

        <td>
            <button class="btn btn-default btn-block" role="remove-secret" data-uuid="_{{ uuid }}">Delete</button>
        </td>
    </tr>
</script>