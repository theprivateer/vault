<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}" class="h-full">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <meta name="referrer" content="no-referrer">

        <link rel="icon" href="/favicon.ico" sizes="any">

        @vite('resources/js/app.ts')
        <x-inertia::head />
    </head>
    <body class="h-full font-sans antialiased">
        <x-inertia::app />
    </body>
</html>
