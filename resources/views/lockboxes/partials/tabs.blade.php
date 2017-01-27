<div class="clearfix" style="margin-bottom: 15px;">
    <h3 class="pull-left" style="margin-top: 0;">{{ $lockbox->name }}</h3>

    <a href="{{ route('lockbox.show', $lockbox->uuid) }}" class="btn btn-default pull-right">Preview</a>

</div>

<ul class="nav nav-tabs">
    <li role="presentation"@if($tab == 'edit') class="active"@endif><a href="{{ route('lockbox.edit', $lockbox->uuid) }}"><i class="fa fa-cog"></i> Settings</a></li>
    <li role="presentation"@if($tab == 'secrets') class="active"@endif><a href="{{ route('secret.edit', $lockbox->uuid) }}"><i class="fa fa-key"></i> Secrets</a></li>
    <li role="presentation"@if($tab == 'files') class="active"@endif><a href="{{ route('file.edit', $lockbox->uuid) }}"><i class="fa fa-file"></i> Files</a></li>
</ul>
