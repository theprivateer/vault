<?php

namespace Database\Factories;

use App\Rules\Envelope;

/**
 * Correctly shaped envelopes for fixtures and tests.
 *
 * The bodies are random noise. Nothing on the server can decrypt an envelope,
 * so a fixture that *could* be decrypted would exercise a path the application
 * does not have — round-trip decryption is proved in the crypto suite, against
 * real keys.
 *
 * What matters here is the header. These have to pass the same shape validation
 * a real client's output does, or factories and requests would quietly diverge
 * from what the API accepts.
 */
final class EnvelopeFixtures
{
    /** @param  int  $bodyBytes  ciphertext and tag, excluding the header and nonce. */
    public static function envelope(int $bodyBytes = 64): string
    {
        return base64_encode(
            chr(Envelope::SUPPORTED_VERSIONS[0])
                .chr(Envelope::SUPPORTED_ALGORITHMS[0])
                .random_bytes(24 + max($bodyBytes, 17))
        );
    }

    /** A sealed box: an ephemeral X25519 public key, then an envelope. */
    public static function sealedEnvelope(): string
    {
        return base64_encode(
            random_bytes(Envelope::SEALED_PREFIX_BYTES)
                .(string) base64_decode(self::envelope(48), true)
        );
    }
}
