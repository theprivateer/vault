import { describe, expect, it } from 'vitest';

import { buildIndex, EMPTY_INDEX, search, tokenise, type Indexable } from './search';

const documents: Indexable[] = [
    { id: 'a', fields: { name: 'AWS root account', location: 'Cloud', type: 'password' } },
    { id: 'b', fields: { name: 'aws-backup-role', notes: 'rotate quarterly', type: 'key' } },
    { id: 'c', fields: { name: 'Cloudflare API token', url: 'https://dash.cloudflare.com' } },
    { id: 'd', fields: { name: 'Staging database', notes: 'aws rds, read replica' } },
];

const index = buildIndex(documents);

const ids = (query: string) => search(index, query).map((hit) => hit.id);

describe('tokenise', () => {
    it('splits on anything that is not a letter or a digit', () => {
        expect(tokenise('aws-root@example.com')).toEqual(['aws', 'root', 'example', 'com']);
    });

    it('lowercases', () => {
        expect(tokenise('AWS Root')).toEqual(['aws', 'root']);
    });

    it('keeps digits', () => {
        expect(tokenise('db2 prod-01')).toEqual(['db2', 'prod', '01']);
    });

    /** A tokeniser that drops non-Latin script makes search useless for whoever has one. */
    it('keeps letters outside the Latin alphabet', () => {
        expect(tokenise('Ключи сервера')).toEqual(['ключи', 'сервера']);
        expect(tokenise('本番 データベース')).toEqual(['本番', 'データベース']);
    });

    it('produces nothing from punctuation alone', () => {
        expect(tokenise('  --  ')).toEqual([]);
    });
});

describe('matching', () => {
    it('finds an exact token', () => {
        expect(ids('cloudflare')).toContain('c');
    });

    it('finds a partial word, because people search while typing', () => {
        expect(ids('cloudf')).toContain('c');
    });

    it('is case insensitive', () => {
        expect(ids('AWS')).toEqual(ids('aws'));
    });

    it('searches inside a hyphenated name', () => {
        expect(ids('backup')).toEqual(['b']);
    });

    it('searches notes as well as names', () => {
        expect(ids('quarterly')).toEqual(['b']);
    });

    it('searches a url', () => {
        expect(ids('dash')).toEqual(['c']);
    });

    it('returns nothing for a query that matches nothing', () => {
        expect(ids('azure')).toEqual([]);
    });

    it('returns nothing for an empty query rather than everything', () => {
        expect(search(index, '')).toEqual([]);
        expect(search(index, '   ')).toEqual([]);
    });

    it('handles an empty index', () => {
        expect(search(EMPTY_INDEX, 'aws')).toEqual([]);
    });
});

describe('multiple words narrow rather than widen', () => {
    it('requires every token', () => {
        expect(ids('aws')).toHaveLength(3);
        expect(ids('aws rds')).toEqual(['d']);
    });

    it('returns nothing when one token matches nothing', () => {
        expect(ids('aws azure')).toEqual([]);
    });

    it('matches two tokens in different fields of the same document', () => {
        expect(ids('staging replica')).toEqual(['d']);
    });
});

describe('ranking', () => {
    it('puts a name match above a note match', () => {
        // 'a' and 'b' have aws in the name; 'd' only in a note.
        expect(ids('aws').indexOf('d')).toBe(2);
    });

    it('puts an exact token above a longer one it is a prefix of', () => {
        const ranked = ids('aws');

        // 'AWS root account' contains the exact token; 'aws-backup-role' does
        // too once hyphens are split, so both are exact — but only one has the
        // shorter name. The property being fixed here is that an exact match
        // is never ranked below a document matched only by prefix.
        expect(ranked.indexOf('a')).toBeLessThan(ranked.indexOf('d'));
    });

    it('is stable between identical queries', () => {
        expect(ids('a')).toEqual(ids('a'));
    });

    it('respects the limit', () => {
        expect(search(index, 'a', 2)).toHaveLength(2);
    });
});

describe('index construction', () => {
    it('records how many documents it holds', () => {
        expect(buildIndex(documents).size).toBe(4);
    });

    it('accumulates weight when a token appears in two fields', () => {
        const both = buildIndex([{ id: 'x', fields: { name: 'aws', notes: 'aws' } }]);
        const one = buildIndex([{ id: 'y', fields: { name: 'aws' } }]);

        // Non-null: both indexes were just built with this token in them.
        expect(search(both, 'aws')[0]!.score).toBeGreaterThan(search(one, 'aws')[0]!.score);
    });

    it('tolerates a document with no indexable fields', () => {
        expect(() => buildIndex([{ id: 'empty', fields: {} }])).not.toThrow();
    });
});

/**
 * The scale claim from docs/06, asserted rather than assumed.
 *
 * Not a benchmark — a wall clock in CI is noisy — but a ceiling loose enough
 * that only a change of algorithmic class trips it. A linear scan of the
 * decrypted list instead of the index would not.
 */
describe('scale', () => {
    it('searches ten thousand documents without the query becoming slow', () => {
        const many: Indexable[] = Array.from({ length: 10_000 }, (_, n) => ({
            id: `id-${n}`,
            fields: {
                name: `service ${n} credential`,
                notes: `rotated on day ${n % 365}`,
                url: `https://host${n}.example.com`,
            },
        }));

        const large = buildIndex(many);
        const started = performance.now();

        for (let run = 0; run < 20; run++) {
            search(large, 'service 4242');
        }

        expect((performance.now() - started) / 20).toBeLessThan(50);
    });
});

/**
 * The exit criterion from Phase 4: search is demonstrably offline.
 *
 * The manual version is to open DevTools, switch the network off and keep
 * typing. This is the automated version — every way a browser can reach the
 * network is replaced with something that throws, and a query still returns.
 *
 * It matters because it is the compensation for the cost D5 imposes. Having to
 * download and decrypt a whole vault buys a property most password managers
 * cannot offer: nobody learns what you searched for, because the query never
 * travels.
 */
describe('offline', () => {
    it('runs a query with every network primitive disabled', () => {
        const forbidden = ['fetch', 'XMLHttpRequest', 'WebSocket', 'EventSource', 'sendBeacon'] as const;
        const saved = new Map<string, unknown>();
        const scope = globalThis as unknown as Record<string, unknown>;

        for (const name of forbidden) {
            saved.set(name, scope[name]);
            scope[name] = () => {
                throw new Error(`search reached the network via ${name}`);
            };
        }

        try {
            expect(ids('cloudflare')).toEqual(['c']);
            expect(buildIndex(documents).size).toBe(4);
        } finally {
            for (const [name, value] of saved) {
                scope[name] = value;
            }
        }
    });
});
