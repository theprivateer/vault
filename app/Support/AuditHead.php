<?php

namespace App\Support;

/**
 * Where the audit chain currently reaches.
 *
 * A typed value rather than a stdClass off the query builder, because both
 * things that read it — the verifier and the daily anchor — are comparing it
 * against something, and a silently-null property in a comparison would report
 * "the chain is intact" for the wrong reason.
 */
final readonly class AuditHead
{
    public function __construct(
        public int $seq,
        /** base64. 32 zero bytes before anything has been recorded. */
        public string $hash,
    ) {}

    public function bytes(): string
    {
        return (string) base64_decode($this->hash, true);
    }
}
