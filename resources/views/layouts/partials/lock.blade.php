<?php if( ! isset($vault)) $vault = Auth::user()->currentVault; ?>

@if(empty($vault->control))
    <div class="alert alert-danger text-center">
        This vault does not have a master password set for client-side encryption. <a href="{{ route('vault.edit', $vault->uuid) }}">Set one now...</a>
    </div>
@endif


@section('scripts')
    @parent

    <script>
        function decryptFields()
        {
            $('[data-encrypted]').each(function(e) {

                var decrypted = decryptForCurrentVault($(this).data('encrypted'));

                // if it's an input...
                if($(this).is('input'))
                {
                    $(this).val(decrypted);
                } else if(decrypted != '')
                {
                    if($(this).data('paranoid'))
                    {
                        $(this).html('******');
                    } else
                    {
                        // if it's not paranoid
                        $(this).html(decrypted);
                    }

                    // if it's clipboardable
                    if($(this).data('clipboardable'))
                    {
                        $('<button class="btn btn-empty" role="clipboard-copy" data-toggle="tooltip" title="Copy to clipboard"><i class="fa fa-clipboard"></i></button>')
                            .attr('data-clipboard-text', decrypted).insertAfter(this);
                    }
                }
            });

            var clipboard = new Clipboard('[role="clipboard-copy"]');
            $('[data-toggle="tooltip"]').tooltip();
        }

        function encryptForCurrentVault(value)
        {
            @if($vault->control)
            var p = getPasskey();

            return CryptoJS.AES.encrypt(value, p).toString();
            @else
                return value;
            @endif
        }

        function decryptForCurrentVault(value)
        {
            @if($vault->control)

                return CryptoJS.AES.decrypt(
                value, getPasskey()
            ).toString(CryptoJS.enc.Latin1);

            @else

                return value;

            @endif
        }

        function getPasskey(uuid)
        {
            if(uuid == null)
            {
                uuid = '{{ $vault->uuid }}';
            }
            console.log(sessionStorage.getItem('{{ session()->getId() }}.' + uuid));
            return sessionStorage.getItem('{{ session()->getId() }}.' + uuid);
        }

        function setPasskey(passKey, uuid)
        {
            if(uuid == null)
            {
                uuid = '{{ $vault->uuid }}';
            }
            console.log(uuid);
            sessionStorage.setItem('{{ session()->getId() }}.' + uuid, passKey);
        }
    </script>

    @if($vault->control)
        <script>
            var v = getPasskey();

            if(v)
            {
                if(checkPasskey(v))
                {
                    decryptFields()
                } else
                {
                    enterPasskey();
                }
            } else
            {
                enterPasskey();
            }

            function enterPasskey()
            {

                bootbox.prompt({
                    title: 'Please enter the master password for \'{{ $vault->name }}\'',
                    callback: function(result){
                        if(result)
                        {
                            console.log(result);
                            if(checkPasskey(result))
                            {
                                setPasskey(result);

                                decryptFields();
                            } else
                            {
                                window.location = "{{ route('vault.reset') }}";
                            }

                        } else
                        {
                            window.location = "{{ route('vault.reset') }}";
                        }

                    }});
            }

            function checkPasskey(passKey)
            {
                var decrypted = CryptoJS.AES.decrypt('{{ $vault->control }}', passKey);
                console.log(decrypted.toString(CryptoJS.enc.Latin1));

                if(decrypted.toString(CryptoJS.enc.Latin1) && decrypted.toString(CryptoJS.enc.Latin1).length == 36)
                {
                    return true;
                } else
                {
                    return false;
                }
            }

        </script>
    @else
        <script>
            $(document).ready(function() {
                decryptFields();
            });
        </script>
    @endif


@endsection