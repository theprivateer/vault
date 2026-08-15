<?php

namespace App\Http\Requests;

use Illuminate\Support\Facades\Config;

/**
 * Creating the row for a file, before any of its body has been sent.
 *
 * The row comes first so that an interrupted upload can be resumed: the wrapped
 * File Key lives here, and without it a client returning tomorrow would have to
 * start from a new key and re-encrypt everything it had already sent.
 *
 * `chunk_count` is the only new field, and the only one the server has an
 * opinion about. It bounds what a client can claim — a request declaring four
 * billion chunks would otherwise reserve four billion object names — and it is
 * how the server later knows an upload is finished. It is *not* the number any
 * client builds associated data from; that one is inside `payload_ct`, where
 * this server cannot reach it.
 */
class StoreFileRequest extends ItemRequest
{
    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return [
            ...$this->newItemRules('files'),

            'chunk_count' => ['required', 'integer', 'min:1', 'max:'.self::maxChunks()],

            'sort_order' => ['sometimes', 'integer', 'min:0', 'max:65535'],
        ];
    }

    /**
     * The most chunks a file may declare, from the configured ceiling and chunk
     * size. Derived rather than configured separately so the two cannot drift
     * into a state where the count and the size disagree about the same limit.
     */
    public static function maxChunks(): int
    {
        return (int) ceil(Config::integer('vault.files.max_bytes') / Config::integer('vault.files.chunk_bytes'));
    }
}
