<?php


if( ! function_exists('lock'))
{
    function lock($value, $key = null)
    {
        $key = (empty($key)) ? config('vault.key') : $key;

        $key = (empty($key)) ? config('app.key') : $key;

        if (Illuminate\Support\Str::startsWith($key, 'base64:')) {
            $key = base64_decode(substr($key, 7));
        }

        return (new Illuminate\Encryption\Encrypter($key, config('vault.cipher')))->encrypt($value);
    }
}

if( ! function_exists('unlock'))
{
    function unlock($value, $key = null)
    {
        $key = (empty($key)) ? config('vault.key') : $key;

        $key = (empty($key)) ? config('app.key') : $key;

        if (Illuminate\Support\Str::startsWith($key, 'base64:')) {
            $key = base64_decode(substr($key, 7));
        }

        return (new Illuminate\Encryption\Encrypter($key, config('vault.cipher')))->decrypt($value);
    }
}