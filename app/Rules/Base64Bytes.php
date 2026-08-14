<?php

namespace App\Rules;

use Closure;
use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Translation\PotentiallyTranslatedString;

/**
 * Validates an opaque blob by shape and size only.
 *
 * This is the whole of what the server is permitted to check about ciphertext
 * and key material: is it base64, and is it the right number of bytes. It must
 * never parse, interpret or inspect the contents — see the rule recorded in
 * .ai/rules/app.md.
 */
class Base64Bytes implements ValidationRule
{
    public function __construct(
        private readonly ?int $exactBytes = null,
        private readonly int $minBytes = 1,
        private readonly int $maxBytes = 8192,
    ) {}

    public static function exactly(int $bytes): self
    {
        return new self(exactBytes: $bytes);
    }

    public static function between(int $min, int $max): self
    {
        return new self(minBytes: $min, maxBytes: $max);
    }

    /**
     * @param  Closure(string, ?string=): PotentiallyTranslatedString  $fail
     */
    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        if (! is_string($value)) {
            $fail('The :attribute must be a base64 encoded string.');

            return;
        }

        $decoded = base64_decode($value, true);

        if ($decoded === false) {
            $fail('The :attribute must be valid base64.');

            return;
        }

        $length = strlen($decoded);

        if ($this->exactBytes !== null) {
            if ($length !== $this->exactBytes) {
                $fail("The :attribute must be exactly {$this->exactBytes} bytes.");
            }

            return;
        }

        if ($length < $this->minBytes || $length > $this->maxBytes) {
            $fail("The :attribute must be between {$this->minBytes} and {$this->maxBytes} bytes.");
        }
    }
}
