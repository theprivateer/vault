<h1 class="page-header text-center" style="margin-top: 0; margin-bottom: 12px;">
    Vaults
</h1>

<div class="page-header clearfix" style="margin-top: 0;">
    <div class="row">
        @if (Request::route()->getName() != 'vault.index')
        <div class="col-sm-4">
            <a href="{{ route('vault.index') }}" class="btn btn-default btn-block">Back to Vaults</a>
        </div>
        @endif

        <div class="col-sm-4 col-sm-offset-4">
            <a href="{{ route('vault.create') }}" class="btn btn-default btn-block">Create Vault</a>
        </div>
    </div>
</div>