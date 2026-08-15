<?php

use App\Support\ChunkBitmap;

/**
 * The bitmap that tracks which chunks of a file have arrived.
 *
 * Worth its own tests because two of its properties are load-bearing and
 * neither is obvious from the call site: setting a bit twice must not
 * double-count, which is what makes chunk uploads idempotent, and the padding
 * bits of the last byte must never be read as chunks that do not exist, which
 * is what stops a file being declared complete early.
 */
it('starts with every chunk missing', function () {
    $bitmap = ChunkBitmap::empty(5);

    expect($bitmap->missing())->toBe([0, 1, 2, 3, 4])
        ->and($bitmap->count())->toBe(0)
        ->and($bitmap->isComplete())->toBeFalse();
});

it('records chunks independently of the order they arrive in', function () {
    $bitmap = ChunkBitmap::empty(4)->with(3)->with(0)->with(2);

    expect($bitmap->missing())->toBe([1])
        ->and($bitmap->has(3))->toBeTrue()
        ->and($bitmap->has(1))->toBeFalse();
});

/*
 | The idempotency property. A client that never saw the response to its last
 | PUT retries it; if a repeat advanced anything, every dropped response would
 | leave the server's picture of the file a little further from the truth.
 */
it('is unchanged by setting the same chunk twice', function () {
    $once = ChunkBitmap::empty(4)->with(2);
    $twice = $once->with(2);

    expect($twice->base64())->toBe($once->base64())
        ->and($twice->count())->toBe(1);
});

it('is complete only when every chunk is present', function () {
    $bitmap = ChunkBitmap::empty(3)->with(0)->with(1);

    expect($bitmap->isComplete())->toBeFalse()
        ->and($bitmap->with(2)->isComplete())->toBeTrue();
});

/*
 | Nine chunks need two bytes, and the seven spare bits in the second belong to
 | no chunk. If they were ever counted the file would look complete while a
 | chunk was still missing — and a half-uploaded file would be served as whole.
 */
it('never reads the padding bits of the last byte as chunks', function () {
    $bitmap = ChunkBitmap::empty(9);

    expect(strlen($bitmap->bits))->toBe(2);

    for ($index = 0; $index < 9; $index++) {
        $bitmap = $bitmap->with($index);
    }

    expect($bitmap->isComplete())->toBeTrue()
        ->and($bitmap->count())->toBe(9)
        // Every bit of the first byte, and only the top bit of the second.
        ->and(bin2hex($bitmap->bits))->toBe('ff80');
});

it('survives a round trip through base64', function () {
    $bitmap = ChunkBitmap::empty(20)->with(0)->with(7)->with(8)->with(19);

    expect(ChunkBitmap::fromBase64($bitmap->base64(), 20)->missing())->toBe($bitmap->missing());
});

it('refuses a stored bitmap that does not match the chunk count', function () {
    $bitmap = ChunkBitmap::empty(20);

    // A row whose chunk_count and received_chunks disagree is corrupt, and
    // guessing which one is right would be the wrong kind of resilience.
    expect(fn () => ChunkBitmap::fromBase64($bitmap->base64(), 8))
        ->toThrow(InvalidArgumentException::class);

    expect(fn () => ChunkBitmap::fromBase64('not base64!', 8))
        ->toThrow(InvalidArgumentException::class);
});

it('refuses an index outside the file', function () {
    $bitmap = ChunkBitmap::empty(4);

    expect(fn () => $bitmap->has(4))->toThrow(InvalidArgumentException::class)
        ->and(fn () => $bitmap->with(-1))->toThrow(InvalidArgumentException::class);
});

it('refuses a file of no chunks at all', function () {
    // A file with nothing authenticated could have its length changed from zero
    // to anything without a tag ever failing, so the empty case is one chunk.
    expect(fn () => ChunkBitmap::empty(0))->toThrow(InvalidArgumentException::class);
});
