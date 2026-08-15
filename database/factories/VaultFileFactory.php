<?php

namespace Database\Factories;

use App\Models\Lockbox;
use App\Models\VaultFile;
use App\Support\ChunkBitmap;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Str;

/**
 * @extends Factory<VaultFile>
 */
class VaultFileFactory extends Factory
{
    protected $model = VaultFile::class;

    /**
     * A file whose row exists but whose body has not been uploaded, which is the
     * state every real file passes through. `uploaded()` is the finished one.
     *
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        $chunkCount = 2;

        return [
            'uuid' => (string) Str::uuid7(),
            'lockbox_id' => Lockbox::factory(),
            // The manifest. Noise, like every other fixture payload — see
            // EnvelopeFixtures for why a decryptable one would prove nothing.
            'payload_ct' => EnvelopeFixtures::envelope(200),
            'wrapped_item_key' => EnvelopeFixtures::envelope(48),
            'payload_version' => 2,
            'storage_key' => (string) Str::uuid7(),
            'storage_disk' => 'local',
            'chunk_count' => $chunkCount,
            'received_chunks' => ChunkBitmap::empty($chunkCount)->base64(),
            'ciphertext_size' => 0,
            'uploaded_at' => null,
            'sort_order' => 0,
        ];
    }

    /**
     * A file whose chunks have all landed.
     *
     * Sets the bitmap as well as the timestamp: the two are written in one
     * transaction by the real upload path, and a fixture that set only one
     * would let a bug that separates them pass unnoticed.
     */
    public function uploaded(int $chunkCount = 2, int $ciphertextSize = 2048): static
    {
        return $this->state(function () use ($chunkCount, $ciphertextSize): array {
            $bitmap = ChunkBitmap::empty($chunkCount);

            for ($index = 0; $index < $chunkCount; $index++) {
                $bitmap = $bitmap->with($index);
            }

            return [
                'chunk_count' => $chunkCount,
                'received_chunks' => $bitmap->base64(),
                'ciphertext_size' => $ciphertextSize,
                'uploaded_at' => now(),
            ];
        });
    }
}
