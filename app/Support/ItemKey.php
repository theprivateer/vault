<?php

namespace App\Support;

/**
 * One row that holds a key wrapped under the Vault Key.
 *
 * A re-key has to touch lockboxes and secrets alike, and the operation is
 * identical for both — unwrap under the old Vault Key, re-wrap under the new
 * one. This carries just enough to identify the row and write it back, so the
 * rotation code can treat the vault's contents as one flat set rather than
 * repeating itself per table.
 */
final readonly class ItemKey
{
    public function __construct(
        public string $uuid,
        public string $wrappedItemKey,
        public string $table,
        public int $id,
    ) {}
}
