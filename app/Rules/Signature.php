<?php

namespace App\Rules;

use Closure;
use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Translation\PotentiallyTranslatedString;

/**
 * Validates that a value is a base64 Ed25519 signature.
 *
 * Length only. The server cannot verify one of these and must not try: it has
 * no trustworthy copy of the signer's public key — it serves that key too, so
 * checking a signature against it would be checking its own work. Verification
 * belongs in the recipient's browser, against a pinned key.
 */
class Signature implements ValidationRule
{
    public const BYTES = 64;

    /**
     * @param  Closure(string, ?string=): PotentiallyTranslatedString  $fail
     */
    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        if (! is_string($value)) {
            $fail('The :attribute must be a base64 encoded signature.');

            return;
        }

        $decoded = base64_decode($value, true);

        if ($decoded === false) {
            $fail('The :attribute must be valid base64.');

            return;
        }

        if (strlen($decoded) !== self::BYTES) {
            $fail('The :attribute must be a '.self::BYTES.' byte signature.');
        }
    }
}
