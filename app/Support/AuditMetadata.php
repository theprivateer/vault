<?php

namespace App\Support;

use InvalidArgumentException;

/**
 * The structural facts an audit event may carry, and nothing else.
 *
 * **This is the guard on the most likely way this project leaks plaintext.**
 * Everywhere else in the design, a value reaching the server is already
 * ciphertext and there is nothing to get wrong. Here there is a free-form JSON
 * column sitting next to a controller that has the whole request in scope, and
 * "just log the name so the activity feed reads nicely" is a small, reasonable-
 * sounding change that would put decrypted content in a table forever — in a
 * table that is, by design, append-only and impossible to clean up.
 *
 * So the keys are a closed set, exactly like `AAD_CONTEXTS`, and each declares
 * what shape it holds. A key nobody has declared throws. Adding one is a
 * deliberate act with a reviewer attached, which is the point.
 *
 * The rule for whether a key belongs here: **could its value ever differ
 * between two users who did the same thing to different data?** A role, an
 * epoch, a count and a chunk index cannot. A name, a note, a filename, a URL and
 * a search term all can, and none of them is admissible.
 */
final class AuditMetadata
{
    /**
     * Declared keys, and the type each holds.
     *
     * @var array<string, 'int'|'bool'|'enum'>
     */
    private const KEYS = [
        /** A role name, from VaultRole. */
        'role' => 'enum',
        'previous_role' => 'enum',

        /** The vault key epoch a rotation moved to, or a grant was issued at. */
        'key_epoch' => 'int',

        /** How many wrapped keys a re-key rewrote. Structural, and the number
         *  that makes a partial re-key visible after the fact. */
        'rewrapped' => 'int',

        /** How many chunks a file has, and how many bytes were stored. Both are
         *  already plaintext columns on `files`; repeating them leaks nothing
         *  new and makes the event readable on its own. */
        'chunk_count' => 'int',
        'chunk_index' => 'int',
        'bytes' => 'int',

        /** The optimistic-concurrency token an edit moved to. */
        'version' => 'int',

        /** Which archived version a restore reached back for. A number, and the
         *  one fact that makes a restore readable — "went back to version 3"
         *  says what happened without saying a word about what was in it. */
        'restored_from' => 'int',

        /** The retention numbers a vault moved to. Already plaintext columns on
         *  `vaults`; repeating them means the log can answer "when did history
         *  get shortened, and by whom" without a schema archaeology dig. */
        'max_versions' => 'int',
        'max_age_days' => 'int',

        /** How many times a one-time link may be opened. A structural choice
         *  the creator made, not a fact about what was shared. */
        'max_views' => 'int',

        /** Whether a second factor was used, and whether it was a backup code. */
        'second_factor' => 'bool',
        'backup_code' => 'bool',

        /** Why something was removed: a file sweep says 'orphan' or 'purged',
         *  a history sweep says 'expired' (too old) or 'retained' (past the
         *  count a vault keeps). */
        'reason' => 'enum',

        /** How many items an operation covered, e.g. secrets deleted with a
         *  lockbox. A count, never a list of names. */
        'count' => 'int',
    ];

    /**
     * Values an `enum` key may hold.
     *
     * A second closed set, because "enum" on its own would admit any string and
     * the whole guard would come down to a reviewer noticing. These are the
     * complete vocabulary; a value outside it throws.
     *
     * @var list<string>
     */
    private const ENUM_VALUES = ['owner', 'editor', 'viewer', 'orphan', 'purged', 'expired', 'retained'];

    /**
     * Validates and canonicalises metadata for storage.
     *
     * Returns the exact JSON text the row will hold and the chain will hash.
     * Keys are sorted so that two events recording the same facts produce the
     * same bytes regardless of the order a controller happened to build them in
     * — a hash chain over "the same thing, spelled differently" would be a
     * chain over nothing.
     *
     * @param  array<string, mixed>  $metadata
     */
    public static function canonicalise(array $metadata): string
    {
        ksort($metadata);

        foreach ($metadata as $key => $value) {
            self::assertDeclared($key, $value);
        }

        /*
         | Cast to an object so that empty metadata encodes as `{}` and not the
         | `[]` an empty PHP array produces. Both decode to nothing useful, but
         | the chain hashes these bytes: a column that is sometimes an object
         | and sometimes an array is two canonical forms for one absence of
         | facts, and the whole point of a canonical form is that there is one.
         |
         | JSON_THROW_ON_ERROR because a silent `false` here would store the
         | string "false" in a column the chain hashes.
         */
        return json_encode((object) $metadata, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    }

    /**
     * @return list<string>
     */
    public static function declaredKeys(): array
    {
        return array_keys(self::KEYS);
    }

    private static function assertDeclared(string $key, mixed $value): void
    {
        $type = self::KEYS[$key] ?? null;

        if ($type === null) {
            throw new InvalidArgumentException(
                "Audit metadata key [{$key}] is not declared in AuditMetadata::KEYS. Every key is "
                .'declared deliberately, because this column is the shortest path from decrypted '
                .'content to a permanent, append-only record of it. If the value can differ between '
                .'two users doing the same thing to different data, it does not belong here.'
            );
        }

        $ok = match ($type) {
            'int' => is_int($value),
            'bool' => is_bool($value),
            'enum' => is_string($value) && in_array($value, self::ENUM_VALUES, true),
        };

        if (! $ok) {
            throw new InvalidArgumentException(
                "Audit metadata key [{$key}] must hold a declared {$type} value."
            );
        }
    }
}
