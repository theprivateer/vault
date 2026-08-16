<?php

namespace Tests\Support;

use Illuminate\Contracts\Hashing\Hasher;

/**
 * Wraps the real hasher and counts what it was asked to do.
 *
 * The timing property the auth endpoints need is that an unknown address costs
 * the same as a known one, and on these endpoints the cost is entirely one
 * password hash — everything else is a database read and a JSON encode, three
 * orders of magnitude cheaper. So rather than time the two paths and compare
 * them, which is a flaky test on shared CI hardware and a weak one anywhere,
 * this counts the hash operations each path performs and asserts they match.
 *
 * That is the stronger assertion of the two. A stopwatch says the difference
 * was small on this machine on this run; a count says the two paths do the same
 * work, and it fails the moment somebody adds a `Hash::make` to one of them.
 *
 * Real timings, measured rather than asserted, are in
 * docs/07-penetration-test.md.
 */
final class CountingHasher implements Hasher
{
    public int $checks = 0;

    public int $makes = 0;

    public function __construct(private readonly Hasher $inner) {}

    /** @return array<array-key, mixed> */
    public function info($hashedValue): array
    {
        return $this->inner->info($hashedValue);
    }

    /** @param  array<string, mixed>  $options */
    public function make($value, array $options = []): string
    {
        $this->makes++;

        return $this->inner->make($value, $options);
    }

    /** @param  array<string, mixed>  $options */
    public function check($value, $hashedValue, array $options = []): bool
    {
        $this->checks++;

        return $this->inner->check($value, $hashedValue, $options);
    }

    /** @param  array<string, mixed>  $options */
    public function needsRehash($hashedValue, array $options = []): bool
    {
        return $this->inner->needsRehash($hashedValue, $options);
    }
}
