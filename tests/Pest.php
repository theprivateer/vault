<?php

use App\Enums\VaultRole;
use App\Models\Lockbox;
use App\Models\User;
use App\Models\UserIdentity;
use App\Models\UserKeyWrap;
use App\Models\Vault;
use Database\Factories\EnvelopeFixtures;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Str;
use Illuminate\Testing\TestResponse;
use Tests\TestCase;

/*
|--------------------------------------------------------------------------
| Test Case
|--------------------------------------------------------------------------
|
| The closure you provide to your test functions is always bound to a specific PHPUnit test
| case class. By default, that class is "PHPUnit\Framework\TestCase". Of course, you may
| need to change it using the "pest()" function to bind different classes or traits.
|
*/

pest()->extend(TestCase::class)
    ->use(RefreshDatabase::class)
    ->in('Feature');

/*
|--------------------------------------------------------------------------
| Expectations
|--------------------------------------------------------------------------
|
| When you're writing tests, you often need to check that values meet certain conditions. The
| "expect()" function gives you access to a set of "expectations" methods that you can use
| to assert different things. Of course, you may extend the Expectation API at any time.
|
*/

/*
|--------------------------------------------------------------------------
| Functions
|--------------------------------------------------------------------------
|
| While Pest is very powerful out-of-the-box, you may have some testing code specific to your
| project that you don't want to repeat in every file. Here you can also expose helpers as
| global functions to help you to reduce the number of lines of code in your test files.
|
*/

/**
 * Parses a response's Content-Security-Policy header into its directives.
 *
 * @template TResponse of \Symfony\Component\HttpFoundation\Response
 *
 * @param  TestResponse<TResponse>  $response
 * @return array<string, string>
 */
function cspDirectives(TestResponse $response): array
{
    $header = $response->headers->get('Content-Security-Policy') ?? '';

    return collect(explode(';', $header))
        ->map(fn (string $directive): string => trim($directive))
        ->filter()
        ->mapWithKeys(function (string $directive): array {
            [$name, $value] = array_pad(explode(' ', $directive, 2), 2, '');

            return [$name => $value];
        })
        ->all();
}

/**
 * Extracts the nonce the CSP authorises, or an empty string if there is none.
 *
 * @template TResponse of \Symfony\Component\HttpFoundation\Response
 *
 * @param  TestResponse<TResponse>  $response
 */
function cspNonce(TestResponse $response): string
{
    preg_match("/'nonce-([^']+)'/", cspDirectives($response)['script-src'] ?? '', $matches);

    return $matches[1] ?? '';
}

/**
 * Reads a string from a JSON response body.
 *
 * `json()` is typed as mixed, and the guard here is a real assertion: a key
 * that is missing or not a string is a test failure worth seeing directly.
 *
 * @template TResponse of \Symfony\Component\HttpFoundation\Response
 *
 * @param  TestResponse<TResponse>  $response
 */
function jsonString(TestResponse $response, string $key): string
{
    $value = $response->json($key);

    if (! is_string($value)) {
        throw new InvalidArgumentException("Response key [{$key}] is not a string.");
    }

    return $value;
}

/**
 * Reads an array out of a JSON response.
 *
 * The companion to `jsonString`, and it exists for the same reason: a response
 * key is `mixed`, so every reader either checks the shape or quietly indexes
 * into something that is not there. Checking once here means a malformed
 * response fails as "that key is not an array" rather than as a run of confusing
 * assertions about missing offsets.
 *
 * @template TResponse of \Symfony\Component\HttpFoundation\Response
 *
 * @param  TestResponse<TResponse>  $response
 * @return array<array-key, mixed>
 */
function jsonArray(TestResponse $response, string $key): array
{
    $value = $response->json($key);

    if (! is_array($value)) {
        throw new InvalidArgumentException("Response key [{$key}] is not an array.");
    }

    return $value;
}

/**
 * Reads a string from a test payload array.
 *
 * @param  array<string, mixed>  $payload
 */
function payloadString(array $payload, string $key): string
{
    $value = $payload[$key] ?? null;

    if (! is_string($value)) {
        throw new InvalidArgumentException("Payload key [{$key}] is not a string.");
    }

    return $value;
}

/**
 * A vault the given user owns, and a lockbox inside it they may write to.
 *
 * Shared rather than local to one file for the same reason `recoverableAccount`
 * is: two files need it, and two copies that drifted would let both pass while
 * describing different setups. The membership is created explicitly rather than
 * left to a factory state, because a vault without one is unreachable by anybody
 * — the Vault Key exists only as the sealed copy on that row.
 */
function writableLockbox(User $user): Lockbox
{
    $vault = Vault::factory()->create(['owner_id' => $user->getKey()]);

    $vault->memberships()->create([
        'uuid' => (string) Str::uuid7(),
        'user_id' => $user->getKey(),
        'role' => VaultRole::Owner,
        'wrapped_vault_key' => EnvelopeFixtures::sealedEnvelope(),
        'key_epoch' => $vault->key_epoch,
        'accepted_at' => now(),
    ]);

    return Lockbox::factory()->create(['vault_id' => $vault->getKey()]);
}

/**
 * An account with a password wrapping, a recovery wrapping and an identity.
 *
 * Shared rather than local to the recovery tests because the security-alert
 * tests exercise the same two flows from the other side, and a second fixture
 * that drifted from this one would let both files pass while the flow they
 * describe no longer matched.
 */
function recoverableAccount(string $email = 'ada@example.com'): User
{
    $user = User::factory()->create(['email' => $email]);

    UserKeyWrap::factory()->for($user)->create();
    UserKeyWrap::factory()->for($user)->recovery()->create();
    UserIdentity::factory()->for($user)->create();

    return $user;
}

/**
 * @param  array<string, mixed>  $overrides
 * @return array<string, mixed>
 */
function passwordChangePayload(array $overrides = []): array
{
    return array_merge([
        'kdf_salt' => base64_encode(random_bytes(16)),
        'kdf_params' => ['m' => 65536, 't' => 3, 'p' => 1],
        'auth_key' => base64_encode(random_bytes(32)),
        'wrapped_user_key' => base64_encode(random_bytes(74)),
    ], $overrides);
}
