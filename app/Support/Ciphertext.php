<?php

namespace App\Support;

use Illuminate\Contracts\Database\Eloquent\Castable;
use Illuminate\Contracts\Database\Eloquent\CastsAttributes;
use InvalidArgumentException;
use JsonSerializable;
use Stringable;

/**
 * An opaque blob of ciphertext or public key material.
 *
 * **There is deliberately no decrypt() method, and there never will be.** The
 * server holds no key capable of reading any of this, so the type that
 * represents it offers no way to try. A controller cannot accidentally reach
 * through it, and CI greps `app/` for decryption calls besides (SR2).
 *
 * Stored base64-encoded in text columns rather than as binary: Postgres returns
 * BYTEA as a stream resource while SQLite returns a string, and that difference
 * would surface only in production. The 33% overhead is irrelevant at the sizes
 * involved, since file bodies live in object storage rather than the database.
 */
final readonly class Ciphertext implements Castable, JsonSerializable, Stringable
{
    /** Guards against a client posting something enormous into a text column. */
    public const MAX_BYTES = 1_048_576;

    private function __construct(public string $base64) {}

    public static function fromBase64(string $value): self
    {
        $decoded = base64_decode($value, true);

        if ($decoded === false) {
            throw new InvalidArgumentException('Ciphertext must be valid base64.');
        }

        if ($decoded === '') {
            throw new InvalidArgumentException('Ciphertext must not be empty.');
        }

        if (strlen($decoded) > self::MAX_BYTES) {
            throw new InvalidArgumentException('Ciphertext exceeds the maximum size.');
        }

        // Re-encode so the stored form is canonical, regardless of the padding
        // or whitespace the client sent.
        return new self(base64_encode($decoded));
    }

    public static function fromBytes(string $bytes): self
    {
        return self::fromBase64(base64_encode($bytes));
    }

    /** The raw ciphertext. Still ciphertext — this is not a way in. */
    public function bytes(): string
    {
        return (string) base64_decode($this->base64, true);
    }

    public function byteLength(): int
    {
        return strlen($this->bytes());
    }

    public function jsonSerialize(): string
    {
        return $this->base64;
    }

    public function __toString(): string
    {
        return $this->base64;
    }

    /**
     * @return CastsAttributes<self, self>
     */
    public static function castUsing(array $arguments): CastsAttributes
    {
        return new class implements CastsAttributes
        {
            public function get($model, string $key, $value, array $attributes): ?Ciphertext
            {
                if ($value === null) {
                    return null;
                }

                if (! is_string($value)) {
                    throw new InvalidArgumentException('Ciphertext columns must hold a string.');
                }

                return Ciphertext::fromBase64($value);
            }

            public function set($model, string $key, $value, array $attributes): ?string
            {
                if ($value === null) {
                    return null;
                }

                if ($value instanceof Ciphertext) {
                    return $value->base64;
                }

                if (! is_string($value)) {
                    throw new InvalidArgumentException('Ciphertext must be set from a string or a Ciphertext.');
                }

                return Ciphertext::fromBase64($value)->base64;
            }
        };
    }
}
