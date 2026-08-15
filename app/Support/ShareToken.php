<?php

namespace App\Support;

use InvalidArgumentException;

/**
 * The one-way step between a share link's bearer token and what is stored.
 *
 * The token is base64url of 32 random bytes, minted in the browser and never
 * transmitted anywhere but a request body. This class turns it into the
 * `share_links.token_hash` the server keeps.
 *
 * **This is not a decryption path.** It is a hash in the direction the rest of
 * the application already hashes — the same reason `users.auth_key_hash` exists
 * — and nothing here can recover a token or open a payload. The payload beside
 * it is sealed under a key that only ever existed in a URL fragment.
 *
 * BLAKE2b-256 rather than a password hash, and that is not an oversight: the
 * input is 256 bits of uniform randomness, so there is no dictionary to run and
 * no work factor worth paying. Argon2id here would cost a second per redemption
 * and buy nothing.
 */
final class ShareToken
{
    /** Raw bytes in a token. */
    public const BYTES = 32;

    /**
     * Hashes a token exactly as `crypto/sharelink.ts` does, so the two agree.
     *
     * The hash is over the token's **decoded bytes**, not its base64url text.
     * Hashing the text would work as long as both ends spelled it identically
     * and would break the day one of them changed its padding — the same class
     * of trap as canonicalising a signed payload.
     */
    public static function hash(string $token): string
    {
        return base64_encode(sodium_crypto_generichash(self::decode($token), '', 32));
    }

    /**
     * Decodes base64url without padding.
     *
     * Strict: a token that is not exactly 32 bytes never came from this
     * application, and treating it leniently would mean hashing something a
     * caller controls the length of.
     */
    public static function decode(string $token): string
    {
        $normalised = strtr(trim($token), '-_', '+/');
        $decoded = base64_decode(str_pad($normalised, (int) (ceil(strlen($normalised) / 4) * 4), '='), true);

        if ($decoded === false || strlen($decoded) !== self::BYTES) {
            throw new InvalidArgumentException(
                'A share token is '.self::BYTES.' bytes of base64url. This one is not, which means '
                .'it was truncated in transit or was never issued here.'
            );
        }

        return $decoded;
    }
}
