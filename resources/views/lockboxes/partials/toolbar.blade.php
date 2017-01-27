<h1 class="page-header text-center" style="margin-top: 0; margin-bottom: 12px;">
    <a href="{{ route('lockbox.index') }}">
        {{ Auth::user()->currentVault->name }}
        <br />
        @if(Auth::user()->canAddToCurrentVault())
            <a href="{{ route('lockbox.create') }}" class="btn btn-default btn-sm">Create Lockbox</a>
        @endif

        @if(Auth::user()->owns())
            <a href="{{ route('vault.edit', Auth::user()->currentVault->uuid) }}" class="btn btn-default btn-sm">Settings</a>
        @endif
    </a>
</h1>