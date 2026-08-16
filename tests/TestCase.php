<?php

namespace Tests;

use Illuminate\Foundation\Testing\TestCase as BaseTestCase;
use Illuminate\Support\Facades\Vite;

abstract class TestCase extends BaseTestCase
{
    /**
     * Asset tags are always rendered from the built manifest, never from a
     * running dev server.
     *
     * `public/hot` is written by `npm run dev` and deleted when it stops
     * cleanly — which it does not always do. A stale one left behind by a dev
     * session weeks ago silently switched every page render in this suite onto
     * the dev-server path, where there is no manifest, no hashed filename and
     * no integrity attribute. The assertions kept passing, against tags nothing
     * in production will ever emit.
     *
     * Pointing the hot file somewhere that cannot exist makes the suite assert
     * against real build output, which is what tests/Feature/SecurityHeadersTest
     * has always claimed to do. The cost is that the assets must be built
     * before the suite runs; CI does that already, and so does `composer setup`.
     */
    protected function setUp(): void
    {
        parent::setUp();

        Vite::useHotFile(storage_path('framework/testing/no-such-hot-file'));
    }
}
