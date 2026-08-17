<?php

use App\Enums\AuditAction;
use App\Models\AuditEvent;
use App\Models\User;
use App\Models\Vault;
use App\Models\VaultMembership;
use Illuminate\Support\Facades\DB;

/**
 * The invariants only the production database can be asked about (Phase 12, task 1).
 *
 * The rest of the suite runs on SQLite, which is fine for behaviour and blind to
 * exactly the thing that matters here: **three columns hold bytes somebody
 * signed, and the database must not have an opinion about them.**
 *
 * On SQLite a column type is close to a comment — everything is text underneath
 * — so `json` and `jsonb` behave identically and nothing would ever notice the
 * difference. On Postgres they are two different data types, and `jsonb`
 * normalises whitespace, reorders keys and drops duplicates. Any one of those
 * turns a valid signature into one no recipient can verify, failing in a way
 * that looks exactly like tampering, on rows that were written correctly.
 *
 * These tests assert the *property* — bytes in, identical bytes out — rather
 * than only the type name, because the property is what is actually relied on.
 * The type assertions are there as well, so a failure names the trap rather than
 * leaving somebody to work out why a signature stopped verifying.
 *
 * Skipped on any other driver instead of failing: the question is meaningless
 * where a column type is not enforced, and a test that reported a problem on
 * SQLite would be reporting one that does not exist there.
 */
beforeEach(function () {
    if (DB::connection()->getDriverName() !== 'pgsql') {
        $this->markTestSkipped('Column storage semantics are a Postgres question.');
    }
});

/**
 * The declared type of one column, as the database understands it.
 *
 * Answers 'missing' rather than throwing on an unknown column, so a renamed
 * column fails as "expected json, got missing" — which names the problem —
 * rather than as an exception from inside a helper.
 */
function columnType(string $table, string $column): string
{
    $type = DB::selectOne(
        'select data_type from information_schema.columns where table_name = ? and column_name = ?',
        [$table, $column]
    );

    return is_object($type) && is_string($type->data_type ?? null) ? $type->data_type : 'missing';
}

/*
 | Deliberately hostile JSON: keys out of alphabetical order, a duplicate key,
 | irregular whitespace, an escaped solidus and a non-ASCII character.
 |
 | Nothing writes a payload that looks like this — a real grant is canonical —
 | and that is exactly the point. A canonical string survives `jsonb` by luck, so
 | a test using one would pass under the type this must never have.
 |
 | Measured against Postgres 17, storing this same string in three columns:
 |
 |   json   {"v":1, "role":"editor",  "role":"viewer", "url":"…/a\/b", …}   identical
 |   text   {"v":1, "role":"editor",  "role":"viewer", "url":"…/a\/b", …}   identical
 |   jsonb  {"v": 1, "url": "…/a/b", "who": "…", "role": "viewer"}          changed
 |
 | `jsonb` reordered the keys, normalised the whitespace, unescaped the solidus,
 | and dropped the duplicate `role` — keeping `viewer` where the signed bytes
 | said `editor`. Any one of those makes the signature fail to verify; the last
 | one changes what the document says.
 */
const AWKWARD = '{"v":1, "role":"editor",  "role":"viewer", "url":"https://example.com/a\/b", "who":"Ada Lovelace — owner"}';

describe('columns holding signed bytes', function () {
    it('stores a grant payload as json, never jsonb', function () {
        // json preserves the input text; jsonb parses it into a normalised
        // binary form and can never give the original bytes back.
        expect(columnType('vault_memberships', 'grant_payload'))->toBe('json');
    });

    it('gives back a grant payload byte for byte', function () {
        $vault = Vault::factory()->create();
        $membership = VaultMembership::factory()->for($vault)->create(['grant_payload' => AWKWARD]);

        expect($membership->fresh()?->grant_payload)->toBe(AWKWARD);
    });

    it('gives back audit metadata byte for byte, because the chain hashes it', function () {
        $user = User::factory()->create();

        // Written through the query builder rather than AuditLog, which
        // canonicalises: the question here is what the *column* does to bytes it
        // is handed, not what the application hands it.
        DB::table('audit_events')->insert([
            'seq' => 9_999,
            'action' => AuditAction::AccountExported->value,
            'actor_uuid' => $user->uuid,
            'metadata' => AWKWARD,
            'prev_hash' => str_repeat('0', 64),
            'hash' => str_repeat('1', 64),
            'created_at' => now(),
        ]);

        expect(columnType('audit_events', 'metadata'))->toBe('text')
            ->and(DB::table('audit_events')->where('seq', 9_999)->value('metadata'))->toBe(AWKWARD);
    });

    it('gives back a rotation payload byte for byte', function () {
        expect(columnType('user_identity_archive', 'rotation_payload'))->toBe('text');
    });
});

/*
 | Ciphertext is base64 in `text` columns rather than BYTEA, and this is where
 | that decision pays. Postgres returns BYTEA as a stream resource and SQLite
 | returns a string — a divergence that would only ever have surfaced in
 | production, on the one type of value that must survive intact.
 */
describe('ciphertext columns', function () {
    it('returns ciphertext as a string rather than a stream', function () {
        $vault = Vault::factory()->create();

        expect(columnType('vaults', 'payload_ct'))->toBe('text')
            ->and($vault->fresh()?->payload_ct->base64)->toBeString();
    });
});

/*
 | The append-only log's third defence is a database grant the application role
 | cannot undo:
 |
 |   REVOKE UPDATE, DELETE ON audit_events FROM vault_app;
 |
 | It is not applied here — the test database connects as the owner, as a dev
 | database should — so this asserts the two layers that *are* code, and says
 | plainly that the third is a deployment step rather than pretending it is
 | covered. See docs/05 Phase 12 and the runbook.
 */
it('refuses to update or delete an audit event in code, whatever the grants say', function () {
    $event = AuditEvent::query()->create([
        'seq' => 1,
        'action' => AuditAction::LoggedIn,
        'metadata' => '{}',
        'prev_hash' => str_repeat('0', 64),
        'hash' => str_repeat('2', 64),
        'created_at' => now(),
    ]);

    expect(fn () => $event->update(['action' => AuditAction::LoggedOut]))->toThrow(RuntimeException::class)
        ->and(fn () => $event->delete())->toThrow(RuntimeException::class);
});
