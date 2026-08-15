<?php

namespace App\Support;

use InvalidArgumentException;

/**
 * Which chunks of a file have arrived.
 *
 * One bit per chunk, base64 in a text column like everything else here. A
 * counter would be a third of the size and would be wrong: chunk uploads are
 * idempotent PUTs, so a client retrying one that already landed would advance a
 * counter a second time and make an incomplete file look finished. A bitmap
 * cannot be double-counted, which is the property that matters.
 *
 * This holds no ciphertext. It is metadata the server is entitled to — it has to
 * know what it is still waiting for — and it leaks nothing beyond the chunk
 * count, which is already a column.
 */
final readonly class ChunkBitmap
{
    /**
     * @param  string  $bits  One byte per eight chunks, index 0 in the high bit.
     */
    private function __construct(
        public string $bits,
        public int $chunkCount,
    ) {}

    public static function empty(int $chunkCount): self
    {
        return new self(str_repeat("\0", self::byteLength($chunkCount)), $chunkCount);
    }

    public static function fromBase64(string $value, int $chunkCount): self
    {
        $decoded = base64_decode($value, true);

        if ($decoded === false || strlen($decoded) !== self::byteLength($chunkCount)) {
            throw new InvalidArgumentException('The chunk bitmap does not match the chunk count.');
        }

        return new self($decoded, $chunkCount);
    }

    public function base64(): string
    {
        return base64_encode($this->bits);
    }

    public function has(int $index): bool
    {
        $this->assertInRange($index);

        return (ord($this->bits[intdiv($index, 8)]) & $this->mask($index)) !== 0;
    }

    /** Returns a new bitmap with the bit set. Setting a set bit is a no-op. */
    public function with(int $index): self
    {
        $this->assertInRange($index);

        $byte = intdiv($index, 8);
        $bits = $this->bits;
        $bits[$byte] = chr(ord($bits[$byte]) | $this->mask($index));

        return new self($bits, $this->chunkCount);
    }

    /**
     * @return list<int>
     */
    public function missing(): array
    {
        $missing = [];

        for ($index = 0; $index < $this->chunkCount; $index++) {
            if (! $this->has($index)) {
                $missing[] = $index;
            }
        }

        return $missing;
    }

    public function isComplete(): bool
    {
        return $this->missing() === [];
    }

    public function count(): int
    {
        $set = 0;

        for ($index = 0; $index < $this->chunkCount; $index++) {
            if ($this->has($index)) {
                $set++;
            }
        }

        return $set;
    }

    /**
     * The trailing bits of the last byte belong to no chunk and stay zero.
     * `missing()` and `count()` walk the chunk count rather than the bytes, so
     * they can never be read as a chunk that does not exist.
     */
    private static function byteLength(int $chunkCount): int
    {
        if ($chunkCount < 1) {
            throw new InvalidArgumentException('A file has at least one chunk.');
        }

        return intdiv($chunkCount + 7, 8);
    }

    private function mask(int $index): int
    {
        return 1 << (7 - ($index % 8));
    }

    private function assertInRange(int $index): void
    {
        if ($index < 0 || $index >= $this->chunkCount) {
            throw new InvalidArgumentException(
                "Chunk {$index} is outside a file of {$this->chunkCount} chunks."
            );
        }
    }
}
