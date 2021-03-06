<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    @section('head')
    <!-- CSRF Token -->
    <meta name="csrf-token" content="{{ csrf_token() }}">

    <title>{{ config('app.name', 'Vault') }} - Secure All The Things!</title>

    <!-- Styles -->
    <link href="/css/app.css" rel="stylesheet">

    <!-- Fonts -->
    <link href="/css/font-awesome.css" rel="stylesheet">

    <link rel="shortcut icon" href="/img/favicon.png">

    <!-- Scripts -->
    <script>
        window.Laravel = <?php echo json_encode([
            'csrfToken' => csrf_token(),
        ]); ?>
    </script>
    @show
</head>
<body>
    <div id="app">

    <nav class="navbar navbar-default navbar-static-top">
        <div class="container">
            <div class="navbar-header">

                <!-- Collapsed Hamburger -->
                <button type="button" class="navbar-toggle collapsed" data-toggle="collapse" data-target="#app-navbar-collapse">
                    <span class="sr-only">Toggle Navigation</span>
                    <span class="icon-bar"></span>
                    <span class="icon-bar"></span>
                    <span class="icon-bar"></span>
                </button>

                <!-- Branding Image -->
                <a class="navbar-brand" href="{{ route('lockbox.index') }}">
                    {{ config('app.name', 'Vault') }}
                </a>
            </div>

            <div class="collapse navbar-collapse" id="app-navbar-collapse">
                <!-- Left Side Of Navbar -->


                @if (Auth::guest())

                @else
                <ul class="nav navbar-nav">
                    @if(Auth::user()->vaults()->count() > 1)
                        <li class="dropdown">
                            <a href="#" class="dropdown-toggle" data-toggle="dropdown" role="button" aria-expanded="false">
                                Switch <span class="caret"></span>
                            </a>

                            <ul class="dropdown-menu" role="menu">
                                @foreach(Auth::user()->vaults as $vault)
                                    <li @if($vault->id == Auth::user()->current_vault_id) class="active" @endif><a href="{{ route('vault.show', $vault->uuid) }}">{{ $vault->name }}</a></li>
                                @endforeach
                            </ul>
                        </li>
                    @endif
                </ul>

                @if($_hasAlgolia = config('algolia.connections.main.search'))
                <form class="navbar-form navbar-left">
                    <input type="text" class="form-control navbar-search" placeholder="Search Lockboxes" role="lockbox-autocomplete">
                </form>
                @endif
                @endif

                <!-- Right Side Of Navbar -->
                <ul class="nav navbar-nav navbar-right">
                    <!-- Authentication Links -->
                    @if (Auth::guest())
                        <li><a href="{{ url('/login') }}">Login</a></li>
                        @if(config('vault.registrations'))
                        <li><a href="{{ url('/register') }}">Register</a></li>
                        @endif
                    @else
                        <li class="dropdown">
                            <a href="#" class="dropdown-toggle" data-toggle="dropdown" role="button" aria-expanded="false">
                                {{ Auth::user()->name }} <span class="caret"></span>
                            </a>

                            <ul class="dropdown-menu" role="menu">
                                <li><a href="{{ route('user.edit') }}">Edit Profile</a></li>
                                <li><a href="{{ route('vault.index') }}">Manage Vaults</a></li>
                                <li class="divider"></li>
                                <li>
                                    <a href="{{ url('/logout') }}"
                                        onclick="event.preventDefault();
                                                 document.getElementById('logout-form').submit();">
                                        Logout
                                    </a>

                                    <form id="logout-form" action="{{ url('/logout') }}" method="POST" style="display: none;">
                                        {{ csrf_field() }}
                                    </form>
                                </li>
                            </ul>
                        </li>
                    @endif
                </ul>
            </div>
        </div>
    </nav>

    <div class="container">
        <div class="row">
            <div class="col-md-8 col-md-offset-2">
                @include('flash::message')

                @yield('content')

            </div>
        </div>
    </div>

    <footer class="container">


        @if (Auth::check())
        <p class="text-center small"><a href="{{ route('vault.index') }}">Manage Vaults</a></p>
        @endif

        @if(config('vault.credit'))
        <p class="text-center small">Powered by <a href="https://github.com/theprivateer/vault" target="_blank">Vault</a></p>
        @endif

    </footer>


    </div>
    @section('scripts')
    <!-- Scripts -->
    <script src="/js/app.js"></script>
    <script src="/js/vendor/bootbox.min.js"></script>
    <script src="/js/vendor/clipboard.min.js"></script>
    <script src="/js/vendor/aes.js"></script>

    @if( ! empty($_hasAlgolia))
    <script src="https://cdn.jsdelivr.net/algoliasearch/3/algoliasearch.min.js"></script>
    <script src="https://cdn.jsdelivr.net/autocomplete.js/0/autocomplete.min.js"></script>

    <script>
        var client = algoliasearch('{{ config('algolia.connections.main.id') }}', '{{ config('algolia.connections.main.search') }}');

        var index_lockboxes = client.initIndex('lockboxes');

        autocomplete('[role="lockbox-autocomplete"]', {hint: false}, [
            {
                source: autocomplete.sources.hits(index_lockboxes, {hitsPerPage: 10, filters: '{{ Auth::user()->algoliaVaultFilter() }}'}),
                displayKey: 'display',
                templates: {
                    suggestion: function(suggestion) {
                        return suggestion._highlightResult.display.value;
                    }
                }
            }
        ]).on('autocomplete:selected', function(event, suggestion, dataset) {
            window.location = '/lockbox/' + suggestion.uuid;
        });
    </script>
    @endif

    <script>
        function generateUUID() {
            var d = new Date().getTime();
            var uuid = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
                var r = (d + Math.random()*16)%16 | 0;
                d = Math.floor(d/16);
                return (c=='x' ? r : (r&0x3|0x8)).toString(16);
            });
            return uuid;
        }
    </script>
    @show
</body>
</html>
