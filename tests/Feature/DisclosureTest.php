<?php

/**
 * Phase 11, task 10: the threat model has to be in the product, not only in the
 * repository (D10, and adversary A3 in docs/02-threat-model.md).
 *
 * The route is asserted over HTTP; the wording is asserted against the
 * component source, because Inertia renders in the browser and the response
 * body carries a JSON prop blob and an empty div. Reading the file is the only
 * way to assert on copy from here, and the copy is the part worth guarding:
 * anyone can add a security page, and the sentence that decays is the one
 * saying a compromised server can serve malicious JavaScript and nothing in the
 * browser will notice — because that is the sentence somebody softens when a
 * prospective user is reading it.
 */

use App\Models\User;
use App\Models\UserKeyWrap;
use Inertia\Testing\AssertableInertia;

/**
 * The disclosure page's source, which is where its words live.
 *
 * Whitespace is collapsed because the formatter owns the line breaks: a
 * sentence asserted here would otherwise start failing the day Prettier decided
 * to wrap it one word earlier, which says nothing about whether the page still
 * makes the admission.
 */
function disclosureSource(): string
{
    $source = (string) file_get_contents(resource_path('js/pages/Security.vue'));

    return (string) preg_replace('/\s+/', ' ', $source);
}

it('serves the disclosure to a stranger with no account', function () {
    $this->get('/security')
        ->assertOk()
        ->assertInertia(fn (AssertableInertia $page) => $page->component('Security'));
});

/*
 | Signed in as well as signed out. The people most in need of it are the ones
 | already storing things here, and a page reachable only from the sign-in
 | screen is a page nobody sees twice.
 */
it('serves the disclosure to a signed-in user', function () {
    $user = User::factory()->create();
    UserKeyWrap::factory()->for($user)->create();

    $this->actingAs($user)
        ->get('/security')
        ->assertOk()
        ->assertInertia(fn (AssertableInertia $page) => $page->component('Security'));
});

it('still says the server can serve malicious code, and that nothing detects it', function () {
    expect(disclosureSource())
        ->toContain('a compromised server can serve you different code')
        ->toContain('captures your password as you type it')
        // The half that makes the first half honest rather than a caveat.
        ->toContain('Nothing on this page or in this application detects that');
});

it('says the data is permanently unreadable if both credentials are lost', function () {
    expect(disclosureSource())
        ->toContain('permanently')
        ->toContain('including whoever runs this server');
});

/*
 | Linked from both layouts, which between them cover every page. A disclosure
 | nobody can navigate to is the repository copy again, served over HTTP.
 */
it('is linked from both layouts', function (string $layout) {
    expect((string) file_get_contents(resource_path("js/layouts/{$layout}.vue")))
        ->toContain('/security');
})->with(['AppLayout', 'AuthLayout']);
