import { describe, expect, it } from 'vitest';

import {
    ALL_FIELD_KEYS,
    buildPayload,
    fieldsFor,
    hasField,
    INDEXABLE_FIELD_KEYS,
    isKnownType,
    isSensitive,
    labelFor,
    readField,
    searchFieldsFor,
    SECRET_TYPES,
    SECRET_TYPE_ORDER,
    unmappedFields,
    type SecretType,
} from './secretTypes';

/**
 * The schema is a table, so its security properties are asserted as one.
 *
 * That is the whole argument for lib/secretTypes.ts existing: twelve bespoke
 * form blocks would need twelve reviews to establish that no credential is
 * searchable and no token renders unmasked. Here it is a loop.
 */
const ALL: SecretType[] = SECRET_TYPE_ORDER;

/**
 * Keys that authenticate whatever type they appear on.
 *
 * `value` is deliberately not among them: it is a password on a login and a
 * plain string on a text item, which is exactly why the schema answers per type
 * rather than per key. The types where `value` *is* a credential are named in
 * their own test below.
 */
const ALWAYS_CREDENTIAL = ['totp', 'cardNumber', 'cardCvv'];

/** Types whose `value` is the thing that authenticates. */
const VALUE_IS_A_CREDENTIAL: SecretType[] = ['password', 'note', 'key', 'server', 'api'];

describe('the table itself', () => {
    it('describes every type exactly once, in a stable order', () => {
        expect([...new Set(ALL)]).toEqual(ALL);
        expect(new Set(ALL)).toEqual(new Set(Object.keys(SECRET_TYPES)));
    });

    it('gives every type a label and a description', () => {
        for (const type of ALL) {
            expect(SECRET_TYPES[type].label, type).not.toBe('');
            expect(SECRET_TYPES[type].description, type).not.toBe('');
        }
    });

    it('gives every type at least one field of its own, plus notes', () => {
        for (const type of ALL) {
            expect(SECRET_TYPES[type].fields.length, type).toBeGreaterThan(0);
            expect(hasField(type, 'notes'), type).toBe(true);
        }
    });

    it('never repeats a field key within a type', () => {
        for (const type of ALL) {
            const keys = fieldsFor(type).map((field) => field.key);

            expect([...new Set(keys)], type).toEqual(keys);
        }
    });
});

describe('what may be searched', () => {
    /*
     | The standing rule, as an assertion rather than a comment: identifiers and
     | locators are searchable, and anything that authenticates is not. Indexing
     | a password so people can find it by typing it would put every credential
     | into a second in-memory structure with a different lifetime from the
     | payloads — one more thing to wipe correctly on lock, bought for a feature
     | nobody wants.
     |
     | Checked first as the invariant that needs no list at all: a field is
     | masked or it is searchable, never both. Nothing is honestly both, and a
     | field claiming to be would be a credential in the index wearing a reason.
     */
    it('never marks a field both masked and searchable', () => {
        for (const type of ALL) {
            for (const field of fieldsFor(type)) {
                expect(field.sensitive === true && field.indexable === true, `${type}.${field.key}`).toBe(
                    false,
                );
            }
        }
    });

    it('never indexes a key that authenticates on any type', () => {
        for (const type of ALL) {
            for (const field of fieldsFor(type)) {
                if (ALWAYS_CREDENTIAL.includes(field.key)) {
                    expect(field.indexable ?? false, `${type}.${field.key}`).toBe(false);
                }
            }
        }

        for (const key of ALWAYS_CREDENTIAL) {
            expect(INDEXABLE_FIELD_KEYS).not.toContain(key);
        }
    });

    it('never indexes the value of a type whose value is a credential', () => {
        for (const type of VALUE_IS_A_CREDENTIAL) {
            const value = fieldsFor(type).find((field) => field.key === 'value');

            expect(value?.indexable ?? false, type).toBe(false);
        }
    });

    /*
     | Except where the value is not a credential at all. A url item's value is a
     | locator and an email item's is an address — both are things people search
     | for by name, and neither authenticates anything.
     */
    it('indexes the value of the types whose value is an identifier', () => {
        expect(isSensitive('url', 'value')).toBe(false);
        expect(isSensitive('email', 'value')).toBe(false);

        expect(searchFieldsFor({ type: 'email', key: 'work', value: 'ada@example.com' }).identifier).toBe(
            'ada@example.com',
        );
    });

    it('keeps a password out of the index while indexing the username beside it', () => {
        const fields = searchFieldsFor({
            type: 'password',
            key: 'github',
            username: 'ada',
            value: 'hunter2',
            url: 'https://github.com',
        });

        expect(fields.identifier).toBe('ada');
        expect(fields.identifier).not.toContain('hunter2');
        expect(JSON.stringify(fields)).not.toContain('hunter2');
    });

    it('keeps a card number and security code out of the index', () => {
        const fields = searchFieldsFor({
            type: 'card',
            key: 'visa',
            cardholder: 'A Lovelace',
            cardNumber: '4111111111111111',
            cardCvv: '123',
        });

        expect(fields.identifier).toBe('A Lovelace');
        expect(JSON.stringify(fields)).not.toContain('4111');
        expect(JSON.stringify(fields)).not.toContain('123');
    });

    it('indexes the type by its label, which is what people type', () => {
        expect(searchFieldsFor({ type: 'api', key: 'ci token' }).type).toBe('api credential');
    });

    it('carries the location it is given, for the vault-wide index', () => {
        expect(searchFieldsFor({ type: 'text', key: 'x' }, 'Infrastructure').location).toBe('Infrastructure');
    });
});

describe('what is masked', () => {
    it('hides every key that authenticates, on every type carrying it', () => {
        for (const type of ALL) {
            for (const field of fieldsFor(type)) {
                if (ALWAYS_CREDENTIAL.includes(field.key)) {
                    expect(field.sensitive ?? false, `${type}.${field.key}`).toBe(true);
                }
            }
        }
    });

    it('hides the value of every type whose value is a credential', () => {
        for (const type of VALUE_IS_A_CREDENTIAL) {
            expect(isSensitive(type, 'value'), type).toBe(true);
        }
    });

    it('leaves the fields printed on the front of a card visible', () => {
        expect(isSensitive('card', 'cardholder')).toBe(false);
        expect(isSensitive('card', 'cardExpiry')).toBe(false);
        expect(isSensitive('card', 'cardNumber')).toBe(true);
        expect(isSensitive('card', 'cardCvv')).toBe(true);
    });

    /*
     | The same key is not the same kind of thing on every type — which is why
     | `isSensitive` is asked per type and not per key.
     */
    it('treats value as a credential on a login and as plain text on a text item', () => {
        expect(isSensitive('password', 'value')).toBe(true);
        expect(isSensitive('text', 'value')).toBe(false);
    });

    it('errs towards hidden for a field it does not recognise', () => {
        expect(isSensitive('password', 'cardCvv')).toBe(true);
        expect(isSensitive('nonesuch', 'value')).toBe(true);
    });
});

describe('a type this build does not know', () => {
    /*
     | A payload written by a later build must render as an item with
     | unrecognised fields — never a crash, and never a silent reinterpretation
     | under some default schema, which would put a token in a box labelled
     | "note" and mask nothing.
     */
    it('is not mistaken for a known one', () => {
        expect(isKnownType('password')).toBe(true);
        expect(isKnownType('sshCertificate')).toBe(false);
    });

    it('renders its own slug as its label rather than inventing one', () => {
        expect(labelFor('sshCertificate')).toBe('sshCertificate');
        expect(labelFor('api')).toBe('api credential');
    });

    it('still offers notes, and nothing it cannot vouch for', () => {
        expect(fieldsFor('sshCertificate').map((field) => field.key)).toEqual(['notes']);
    });

    it('surfaces everything it holds rather than dropping it', () => {
        const unmapped = unmappedFields({
            type: 'sshCertificate',
            key: 'host key',
            certificate: 'ssh-ed25519 AAAA…',
            validUntil: '2027-01-01',
        });

        expect(unmapped.map((entry) => entry.field.key)).toEqual(['certificate', 'validUntil']);
        expect(unmapped.every((entry) => entry.field.sensitive)).toBe(true);
    });
});

describe('a payload from before its type had fields', () => {
    /*
     | Every `card` created while cards were a single `value` box. The content is
     | still in there, and a schema that simply stopped rendering `value` on a
     | card would make it invisible — indistinguishable, to the person looking at
     | it, from data that had been lost.
     */
    it('keeps showing what the old shape held', () => {
        const legacy = {
            type: 'card',
            key: 'visa',
            value: '4111 1111 1111 1111 exp 03/28',
            notes: '',
        };

        expect(unmappedFields(legacy).map((entry) => entry.value)).toEqual(['4111 1111 1111 1111 exp 03/28']);
    });

    it('does not report structure or empty fields as unmapped content', () => {
        const payload = { type: 'password', key: 'x', value: '', notes: '', paranoid: true };

        expect(unmappedFields(payload)).toEqual([]);
    });

    it('ignores a value that is not a string rather than coercing it', () => {
        expect(unmappedFields({ type: 'text', key: 'x', count: 7 })).toEqual([]);
        expect(readField({ nested: { a: 1 } }, 'nested')).toBe('');
        expect(readField({}, 'missing')).toBe('');
    });
});

describe('buildPayload', () => {
    const draft = {
        type: 'card',
        key: 'visa',
        paranoid: false,
        unknown: {},
        fields: {
            cardholder: 'A A LOVELACE',
            cardNumber: '4111111111111111',
            cardExpiry: '',
            cardCvv: '',
            notes: '',
            value: 'left over from a password item',
            street: 'not shown on a card',
        },
    };

    it('keeps only the fields the type shows', () => {
        const payload = buildPayload(draft);

        expect(payload.cardholder).toBe('A A LOVELACE');
        expect(payload.street).toBeUndefined();
    });

    /*
     | Switch a card to a note and the number must go, rather than lingering in
     | the ciphertext where nothing will ever display it again. Invisible content
     | is still content, and it would travel into every future share and archived
     | version of the item.
     */
    it('drops a value the new type has no field for', () => {
        const payload = buildPayload({ ...draft, type: 'note' });

        expect(payload.cardNumber).toBeUndefined();
        expect(payload.type).toBe('note');
    });

    /*
     | Dropping empties is the privacy-preserving choice, and it is the opposite
     | of what it looks like — which is why it is pinned here rather than left to
     | be "tidied" into writing every key.
     |
     | Writing empty keys would make items of one type a uniform size. Uniformity
     | tightens each type's size range, and tight ranges that differ from one
     | another are exactly what lets the padding bucket suggest a type. Dropping
     | empties lets a sparsely-filled item sit in the same bucket as a much
     | simpler one. Measured: the 128-byte bucket holds eleven of twelve
     | candidate types this way, and eight the other way.
     */
    it('omits empty fields rather than writing them as empty strings', () => {
        const payload = buildPayload(draft);

        expect('cardExpiry' in payload).toBe(false);
        expect('cardCvv' in payload).toBe(false);

        const sparse = JSON.stringify(payload).length;
        const full = JSON.stringify(
            buildPayload({ ...draft, fields: { ...draft.fields, cardExpiry: '03/28', cardCvv: '123' } }),
        ).length;

        expect(sparse).toBeLessThan(full);
    });

    it('always carries value and notes, which every reader may assume', () => {
        const payload = buildPayload(draft);

        expect(payload.value).toBe('');
        expect(payload.notes).toBe('');
    });

    it('carries unplaced fields through untouched', () => {
        const payload = buildPayload({ ...draft, unknown: { legacyNumber: '4111 1111' } });

        expect(payload.legacyNumber).toBe('4111 1111');
    });

    it('records the sensitive flag only when it is set', () => {
        expect('paranoid' in buildPayload(draft)).toBe(false);
        expect(buildPayload({ ...draft, paranoid: true }).paranoid).toBe(true);
    });

    /*
     | The lockbox link is a column, not a payload key — the server enforces that
     | both ends live in the same vault and needs to see the edge. Writing it
     | into the ciphertext as well would put a second, unreadable copy of the
     | same fact somewhere nothing keeps in step with the column.
     */
    it('never writes the lockbox link into the payload', () => {
        const payload = buildPayload({
            ...draft,
            type: 'lockbox',
            fields: { linkedLockboxUuid: '0192-abc', notes: '' },
        });

        expect('linkedLockboxUuid' in payload).toBe(false);
    });
});

describe('ALL_FIELD_KEYS', () => {
    it('covers every key any type declares, without duplicates', () => {
        const declared = new Set(ALL.flatMap((type) => fieldsFor(type).map((field) => field.key)));

        expect(new Set(ALL_FIELD_KEYS)).toEqual(declared);
        expect(ALL_FIELD_KEYS.length).toBe(declared.size);
    });
});
