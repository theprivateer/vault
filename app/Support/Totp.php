<?php

namespace App\Support;

use Illuminate\Support\Str;

/**
 * Time-based one-time passwords (RFC 6238 over RFC 4226 HMAC-OTP).
 *
 * Implemented directly rather than pulled in: it is thirty lines of
 * well-specified arithmetic, and this project has a standing preference for a
 * small, readable dependency surface (adversary A10).
 *
 * **This protects authentication only.** It cannot gate decryption, because
 * decryption never involves the server — a second factor the server checks
 * cannot stand between a user and a key the server does not have. It raises the
 * cost of using stolen credentials to obtain a session; it does nothing for
 * someone who has the password itself, since they can derive the KEK offline
 * from the wrapped key in a stolen database.
 */
final class Totp
{
    /** RFC 4648 base32, which is what authenticator apps expect. */
    private const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    private const DIGITS = 6;

    private const PERIOD = 30;

    /**
     * How many periods either side of now are accepted, to tolerate clock
     * drift. One step each way is the usual compromise between usability and
     * the size of the window an intercepted code stays valid for.
     */
    private const WINDOW = 1;

    /** 160 bits, matching the SHA-1 block the algorithm uses. */
    public static function generateSecret(): string
    {
        return self::encodeBase32(random_bytes(20));
    }

    public static function codeAt(string $secret, int $timestamp): string
    {
        $counter = intdiv($timestamp, self::PERIOD);
        $binary = pack('J', $counter);

        $hash = hash_hmac('sha1', $binary, self::decodeBase32($secret), true);

        // Dynamic truncation, RFC 4226 §5.4.
        $offset = ord($hash[strlen($hash) - 1]) & 0x0F;
        $value = ((ord($hash[$offset]) & 0x7F) << 24)
            | ((ord($hash[$offset + 1]) & 0xFF) << 16)
            | ((ord($hash[$offset + 2]) & 0xFF) << 8)
            | (ord($hash[$offset + 3]) & 0xFF);

        return str_pad((string) ($value % (10 ** self::DIGITS)), self::DIGITS, '0', STR_PAD_LEFT);
    }

    public static function verify(string $secret, string $code, ?int $timestamp = null): bool
    {
        $code = preg_replace('/\s+/', '', $code) ?? '';

        if (! preg_match('/^\d{'.self::DIGITS.'}$/', $code)) {
            return false;
        }

        $now = $timestamp ?? time();
        $valid = false;

        /*
         | Every candidate is evaluated even after a match, so the number of
         | comparisons does not reveal which step matched. hash_equals keeps the
         | comparison itself constant-time.
         */
        for ($step = -self::WINDOW; $step <= self::WINDOW; $step++) {
            $candidate = self::codeAt($secret, $now + ($step * self::PERIOD));

            $valid = hash_equals($candidate, $code) || $valid;
        }

        return $valid;
    }

    public static function provisioningUri(string $secret, string $email, string $issuer): string
    {
        return 'otpauth://totp/'.rawurlencode($issuer).':'.rawurlencode($email).'?'.http_build_query([
            'secret' => $secret,
            'issuer' => $issuer,
            'algorithm' => 'SHA1',
            'digits' => self::DIGITS,
            'period' => self::PERIOD,
        ]);
    }

    /** A single-use backup code, shown once at enrolment and stored hashed. */
    public static function generateBackupCode(): string
    {
        return Str::lower(Str::random(5).'-'.Str::random(5));
    }

    public static function encodeBase32(string $bytes): string
    {
        $bits = '';

        foreach (str_split($bytes) as $byte) {
            $bits .= str_pad(decbin(ord($byte)), 8, '0', STR_PAD_LEFT);
        }

        $output = '';

        foreach (str_split($bits, 5) as $chunk) {
            $output .= self::ALPHABET[(int) bindec(str_pad($chunk, 5, '0', STR_PAD_RIGHT))];
        }

        return $output;
    }

    public static function decodeBase32(string $value): string
    {
        $bits = '';

        foreach (str_split(strtoupper(rtrim($value, '='))) as $character) {
            $index = strpos(self::ALPHABET, $character);

            if ($index === false) {
                continue;
            }

            $bits .= str_pad(decbin($index), 5, '0', STR_PAD_LEFT);
        }

        $output = '';

        foreach (str_split($bits, 8) as $chunk) {
            if (strlen($chunk) === 8) {
                $output .= chr((int) bindec($chunk));
            }
        }

        return $output;
    }
}
