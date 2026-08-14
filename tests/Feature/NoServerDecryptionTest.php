<?php

use App\Support\Ciphertext;
use Illuminate\Support\Facades\File;

/**
 * SR2: there is no decryption path in `app/`, and there never will be.
 *
 * A grep, deliberately. The leak canary next door proves nothing *did* leak on
 * the paths a test exercised; this proves the capability is not present at all,
 * on every path, including ones nobody thought to test.
 *
 * It is also the check most likely to fail usefully in six months, when someone
 * reaches for `Crypt::decryptString()` to solve a problem that feels small. The
 * failure message is meant to be read at that moment.
 */

/**
 * Calls that would mean the server can read user content.
 *
 * `Crypt::` and `decrypt(` cover Laravel's APP_KEY encrypter;
 * `sodium_crypto_*_open` and `openssl_decrypt` cover reaching past it.
 *
 * @var array<string, string>
 */
const FORBIDDEN_CALLS = [
    '/\bCrypt::/' => 'Crypt:: uses APP_KEY, which the server holds. User content must never be reachable with a key the server has.',
    '/(?<![\w>$])decrypt\s*\(/' => 'A decrypt() call in app/. The server holds no key for user content and must not appear to.',
    '/\bopenssl_decrypt\s*\(/' => 'openssl_decrypt in app/.',
    '/\bsodium_crypto_\w*_open\s*\(/' => 'A sodium open/decrypt call in app/.',
    '/\bsodium_crypto_\w*_decrypt\s*\(/' => 'A sodium decrypt call in app/.',
];

/**
 * Strips comments so that documentation *about* the rule does not trip it.
 *
 * `Ciphertext` says in its docblock that it has deliberately no decrypt()
 * method — which the naive grep read as a decrypt() call. Tokenising rather
 * than matching a comment marker keeps that honest in both directions: a real
 * call cannot hide inside something that merely looks like a comment.
 */
function withoutComments(string $php): string
{
    return collect(token_get_all($php))
        ->reject(fn (array|string $token): bool => is_array($token)
            && in_array($token[0], [T_COMMENT, T_DOC_COMMENT], true))
        ->map(fn (array|string $token): string => is_array($token) ? $token[1] : $token)
        ->implode('');
}

/**
 * The one documented exception, and the reason it is written down here rather
 * than quietly excluded: a TOTP seed is an authentication factor the server has
 * to verify, like a password hash. It is not user content, no vault data is
 * ever cast this way, and it cannot gate decryption — because decryption never
 * involves the server. See docs/04-data-model.md.
 *
 * @var array<string, string>
 */
const DOCUMENTED_EXCEPTIONS = [
    'app/Models/User.php' => "'totp_secret_ct' => 'encrypted',",
];

it('contains no decryption call anywhere in app/', function () {
    $offences = [];

    foreach (File::allFiles(app_path()) as $file) {
        $relative = 'app/'.$file->getRelativePathname();
        $contents = withoutComments($file->getContents());

        $allowed = DOCUMENTED_EXCEPTIONS[$relative] ?? null;

        if ($allowed !== null) {
            $contents = str_replace($allowed, '', $contents);
        }

        foreach (FORBIDDEN_CALLS as $pattern => $why) {
            if (preg_match($pattern, $contents) === 1) {
                $offences[] = "{$relative}: {$why}";
            }
        }
    }

    expect($offences)->toBe([], implode("\n", $offences));
});

/**
 * The type that represents stored ciphertext offers no way to read it.
 *
 * This is the compile-time-ish half of the same guarantee: even with a key, a
 * controller has nothing to call. It is the direct answer to the 2017
 * `getKeyAttribute()` accessor, which decrypted on property access and so put
 * plaintext one `->key` away from every view.
 */
it('exposes no way to read a Ciphertext back', function () {
    $methods = collect((new ReflectionClass(Ciphertext::class))->getMethods())
        ->filter(fn (ReflectionMethod $method): bool => $method->isPublic())
        ->map(fn (ReflectionMethod $method): string => $method->getName())
        ->values()
        ->all();

    expect($methods)->not->toContain('decrypt', 'open', 'plaintext', 'value');
});

/**
 * The grep is only worth anything if it would actually fire. A pattern that
 * silently stopped matching — a typo in the regex, a change to how files are
 * walked — would leave a green test guarding nothing.
 */
it('would catch a decryption call if one were added', function () {
    $sample = '<?php $x = Crypt::decryptString($blob); openssl_decrypt($a, $b, $c); '
        .'sodium_crypto_secretbox_open($a, $b, $c); decrypt($y); '
        .'sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($a, $b, $c, $d);';

    $matched = collect(FORBIDDEN_CALLS)
        ->keys()
        ->reject(fn (string $pattern): bool => preg_match($pattern, $sample) === 1)
        ->all();

    expect($matched)->toBe([]);
});
