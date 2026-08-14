<?php

namespace App\Rules;

use Closure;
use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Translation\PotentiallyTranslatedString;

/**
 * Validates that a blob is shaped like an envelope this build understands.
 *
 * The header is metadata, not content: a version byte and an algorithm byte,
 * both public by design, followed by a nonce that is also public. Checking them
 * lets the server reject malformed or downgrade-flavoured input at the edge
 * instead of storing it and letting a browser discover the problem later.
 *
 * It stops at the header. Nothing here decrypts, and nothing here looks past
 * byte two — see the rule in .ai/rules/app.md.
 *
 *   [ver:1][alg:1][nonce:24][ciphertext + tag:>=17]
 */
class Envelope implements ValidationRule
{
    /** Matches ENVELOPE_VERSION / ALG_XCHACHA20_POLY1305 in resources/js/crypto/envelope.ts. */
    public const SUPPORTED_VERSIONS = [1];

    public const SUPPORTED_ALGORITHMS = [1];

    /** ver + alg + nonce + tag, with at least one byte of ciphertext. */
    public const MIN_BYTES = 1 + 1 + 24 + 16 + 1;

    /** A sealed box prefixes the envelope with a 32-byte ephemeral public key. */
    public const SEALED_PREFIX_BYTES = 32;

    public function __construct(
        private readonly int $maxBytes,
        private readonly bool $sealed = false,
    ) {}

    public static function upTo(int $maxBytes): self
    {
        return new self($maxBytes);
    }

    /** A key sealed to an X25519 public key, as on a membership row. */
    public static function sealed(int $maxBytes = 512): self
    {
        return new self($maxBytes, sealed: true);
    }

    /**
     * @param  Closure(string, ?string=): PotentiallyTranslatedString  $fail
     */
    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        if (! is_string($value)) {
            $fail('The :attribute must be a base64 encoded envelope.');

            return;
        }

        $decoded = base64_decode($value, true);

        if ($decoded === false) {
            $fail('The :attribute must be valid base64.');

            return;
        }

        $prefix = $this->sealed ? self::SEALED_PREFIX_BYTES : 0;
        $length = strlen($decoded);

        if ($length < $prefix + self::MIN_BYTES || $length > $this->maxBytes) {
            $fail("The :attribute is not a plausible envelope length ({$length} bytes).");

            return;
        }

        $header = unpack('Cversion/Calgorithm', substr($decoded, $prefix, 2));

        if ($header === false) {
            $fail('The :attribute has an unreadable envelope header.');

            return;
        }

        if (! in_array($header['version'], self::SUPPORTED_VERSIONS, true)) {
            $fail('The :attribute uses an unsupported envelope version.');

            return;
        }

        if (! in_array($header['algorithm'], self::SUPPORTED_ALGORITHMS, true)) {
            $fail('The :attribute uses an unsupported envelope algorithm.');
        }
    }
}
