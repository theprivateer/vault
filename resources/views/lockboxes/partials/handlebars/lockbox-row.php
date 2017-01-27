<script id="lockbox-row" type="text/x-handlebars-template">
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
                <div class="input-group">
                    <div class="input-group-addon"><i class="fa fa-lock"></i></div>
                    <select name="secrets[{{ uuid }}][linked_lockbox_id]" class="form-control" placeholder="Select...">
                        <option value="0" disabled selected>Select Lockbox...</option>
                        <?php foreach((new Vault\Lockboxes\LockboxRepository)->getListFor(Illuminate\Support\Facades\Auth::user()) as $l): ?>
                            <?php if(isset($lockbox) && $lockbox->id == $l->id) continue ?>
                            <option value="<?= $l->id ?>"><?= $l->name ?> [<?= $l->vault->name ?>]</option>
                        <?php endforeach ?>
                    </select>
                </div>
            </div>
        </td>

        <td>
        </td>

        <td>
            <button class="btn btn-default btn-block" role="remove-secret" data-uuid="_{{ uuid }}">Delete</button>
        </td>
    </tr>
</script>