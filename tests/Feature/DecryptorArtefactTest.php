<?php

/**
 * The offline decryptor, checked as a built artefact (Phase 12, task 3).
 *
 * This file is unusual: nothing in the application loads it, no route serves it
 * through the framework, and no other test would notice if it broke. It is
 * downloaded once and kept for years, and the moment it matters is the moment
 * nobody is available to fix it — which is exactly the shape of thing that rots
 * unwatched.
 *
 * The hash check is the one that would actually catch a silent break. The page
 * allows its own script by SHA-256 rather than by 'unsafe-inline', so any change
 * to the inlining step that alters a byte after the hash is computed produces a
 * file that refuses to run, with no error anywhere until somebody opens it in
 * five years' time.
 *
 * Assets must be built first, same as the Vite manifest assertions — see
 * .ai/rules/tests.md.
 */
function decryptor(): string
{
    $path = public_path('build/vault-decryptor.html');

    if (! file_exists($path)) {
        throw new RuntimeException(
            'public/build/vault-decryptor.html is missing. Run `npm run build` (or `npm run build:decryptor`).'
        );
    }

    return (string) file_get_contents($path);
}

function decryptorScript(): string
{
    preg_match('/<script type="module">(.*)<\/script>/s', decryptor(), $matches);

    return $matches[1] ?? '';
}

it('allows its own script by hash, and the hash matches the script', function () {
    preg_match("/script-src 'sha256-([^']+)'/", decryptor(), $declared);

    $hash = $declared[1] ?? null;

    expect($hash)->not->toBeNull()
        ->and($hash)->toBe(base64_encode(hash('sha256', decryptorScript(), true)));
});

/*
 | The claim the whole artefact rests on. "This page does not send your secrets
 | anywhere" is checkable by reading one line of the file rather than by auditing
 | 37 KB of bundle underneath it — but only while the line says 'none'.
 */
it('forbids every network request in its own content policy', function () {
    expect(decryptor())->toContain("default-src 'none'")
        ->and(decryptor())->not->toContain('connect-src')
        ->and(decryptor())->not->toContain('img-src');
});

it('references nothing outside itself, because there is nothing to fetch it from', function () {
    // No src=, no href=, no url() pointing anywhere. A dead link in this file is
    // a dead link on the one day it is opened.
    expect(decryptor())->not->toMatch('/(src|href)="(?!#)[^"]+"/')
        ->and(decryptor())->not->toContain('import(');
});

it('carries the archive format rather than fetching or reimplementing it', function () {
    // The magic and the domain separator both come from crypto/archive.ts. If
    // the bundle ever stopped including it, these would be the first to go.
    expect(decryptorScript())->toContain('VAULTARC')
        ->and(decryptorScript())->toContain('vault:export:archive:v1');
});

it('leaves no unpoliced second copy of the bundle in public/', function () {
    // The intermediate decryptor.js is removed after inlining. Left behind, it
    // would be the same code served with no content policy at all.
    expect(file_exists(public_path('build/decryptor.js')))->toBeFalse();
});
