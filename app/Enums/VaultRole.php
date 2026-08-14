<?php

namespace App\Enums;

/**
 * What a member may do in a vault.
 *
 * Enforced by the server on every write path. **Not** enforced
 * cryptographically on reads, and it cannot be: every member holds the Vault
 * Key, so every member can decrypt. A viewer who wants a copy of a secret can
 * take one, and no amount of server-side policy changes that.
 *
 * That is a real limitation and it is stated in the UI rather than papered over.
 * See docs/01-brief-and-decisions.md#a-note-on-what-read-only-means.
 */
enum VaultRole: string
{
    case Owner = 'owner';
    case Editor = 'editor';
    case Viewer = 'viewer';

    /** Whether this role may create, update or delete content in the vault. */
    public function canWrite(): bool
    {
        return $this !== self::Viewer;
    }

    /** Whether this role may change membership, rotate keys or delete the vault. */
    public function canAdminister(): bool
    {
        return $this === self::Owner;
    }
}
