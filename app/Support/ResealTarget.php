<?php

namespace App\Support;

use App\Models\Lockbox;
use App\Models\Secret;
use App\Models\Vault;
use App\Models\VaultFile;

/**
 * One row a re-seal may touch, resolved from a UUID the client sent.
 *
 * Exists because a re-seal submission is a flat list of UUIDs spanning four
 * tables, and the alternative — letting the client say which table each one is
 * in — would be letting the client pick which table gets written. Everything
 * here is resolved from the vault downwards, so a UUID that is not in the vault
 * has nowhere to land.
 *
 * `digest` is a checksum over an opaque column, which is not a reading of it:
 * there is no key on this server, and hashing a blob reveals nothing about its
 * contents. It is what lets `VaultResealController` compare-and-swap without
 * shipping every ciphertext back and forth.
 */
final readonly class ResealTarget
{
    private function __construct(
        public string $uuid,
        public string $table,
        public int $id,
        /** The ciphertext exactly as stored, for the atomic guard on update. */
        public string $payloadCt,
        /**
         * BLAKE2b-256 of the decoded ciphertext, base64. Compared with the client's.
         *
         * BLAKE2b to match `hash256` in the crypto core and `ShareToken::hash`, and
         * over the decoded *bytes* rather than the base64 text — the same
         * canonicalisation trap as every other hash in this codebase.
         */
        public string $digest,
    ) {}

    /**
     * Every payload in a vault, keyed by UUID.
     *
     * Trashed rows are excluded, unlike the re-key item set. A soft-deleted item
     * is not being read by anybody, so re-sealing it buys nothing — and its
     * plaintext is not on the page the client decrypted, so it could not
     * honestly be included anyway.
     *
     * `secret_versions` is absent and cannot be added: an archived version is
     * immutable by design, because an archive that could be rewritten is a
     * rollback channel for a credential somebody rotated *because* it leaked.
     *
     * @return array<string, self>
     */
    public static function inVault(Vault $vault): array
    {
        $targets = [self::from('vaults', $vault)];

        $lockboxes = $vault->lockboxes()->get(['id', 'uuid', 'payload_ct']);

        foreach ($lockboxes as $lockbox) {
            $targets[] = self::from('lockboxes', $lockbox);
        }

        $lockboxIds = $lockboxes->modelKeys();

        foreach (Secret::query()->whereIn('lockbox_id', $lockboxIds)->get(['id', 'uuid', 'payload_ct']) as $secret) {
            $targets[] = self::from('secrets', $secret);
        }

        foreach (VaultFile::query()->whereIn('lockbox_id', $lockboxIds)->get(['id', 'uuid', 'payload_ct']) as $file) {
            $targets[] = self::from('files', $file);
        }

        return array_column($targets, null, 'uuid');
    }

    /** Whether the client decrypted the ciphertext this row still holds. */
    public function matches(string $submittedDigest): bool
    {
        return hash_equals($this->digest, $submittedDigest);
    }

    private static function from(string $table, Vault|Lockbox|Secret|VaultFile $model): self
    {
        return new self(
            $model->uuid,
            $table,
            $model->id,
            $model->payload_ct->base64,
            base64_encode(sodium_crypto_generichash($model->payload_ct->bytes(), '', 32)),
        );
    }
}
