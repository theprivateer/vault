/**
 * Search, in the browser, over data the server cannot read.
 *
 * This module is the bill for decision D5. Encrypting every field means the
 * server cannot answer "which of my secrets mention aws", so the client has to,
 * and the only material it can work from is the plaintext it has already
 * decrypted. That constraint has one genuinely pleasant consequence: a query
 * here produces no network traffic at all, so nobody — not the server, not
 * anything watching it — learns what was searched for. That is a stronger
 * privacy property than most password managers offer, and it is worth saying
 * out loud in the interface rather than only in a document.
 *
 * **Why an index rather than a scan.** Filtering an array of a thousand
 * decrypted secrets on every keystroke is fine; ten thousand is not, and the
 * point at which it stops being fine is exactly the point where nobody is
 * watching for it. An inverted index makes the per-keystroke cost proportional
 * to the number of *matches* instead of the size of the vault, and it is forty
 * lines. The scale numbers in docs/06-testing-and-ci.md are measured against
 * this implementation.
 *
 * **What is deliberately not indexed: the secret's value.** Nobody searches
 * for a password by typing the password, and indexing values would put every
 * credential into a second in-memory structure with a different lifetime from
 * the payloads themselves — one more thing to wipe correctly on lock, bought
 * for a feature nobody wants. Names, notes, URLs and types only.
 *
 * **Blind indexes are the alternative, and this is why not.** A server-side
 * searchable index over encrypted data (deterministic tags per keyword) would
 * let the server answer queries without the browser holding everything. It
 * would also give the server a per-keyword equality oracle across all users,
 * which frequency analysis eats alive on a corpus as predictable as credential
 * names. The measurement, not the theory, is what says we do not need to take
 * that trade: see the scale ceiling in docs/06.
 */

/** Fields carry different weight because a name match is a better match. */
export const FIELD_WEIGHTS = {
    name: 8,
    /** The lockbox or vault an item sits in. */
    location: 4,
    /**
     * Identifiers from the typed fields: usernames, hostnames, email addresses,
     * cardholders, cities.
     *
     * One field rather than one per key, because the ranking question is "how
     * good a match is this", not "which column matched" — and a single field
     * means adding a type cannot quietly add a search weight nobody chose.
     *
     * What may populate it is decided by `indexable` in lib/secretTypes.ts,
     * which defaults to false: identifiers and locators are searchable, and
     * anything that authenticates is not.
     */
    identifier: 4,
    url: 2,
    type: 2,
    notes: 1,
} as const;

export type SearchField = keyof typeof FIELD_WEIGHTS;

export interface Indexable {
    id: string;
    fields: Partial<Record<SearchField, string>>;
}

export interface SearchHit {
    id: string;
    score: number;
}

/**
 * Token → the ids containing it, with the accumulated field weight.
 *
 * A Map of Maps rather than a Map of arrays so a document appearing twice under
 * one token (a word in both the name and the notes) adds up rather than
 * appearing twice in the results.
 */
export interface SearchIndex {
    postings: Map<string, Map<string, number>>;
    size: number;
}

/**
 * Splits on anything that is not a letter or a digit, and lowercases.
 *
 * Deliberately blunt: `aws-root@example.com` becomes four tokens, so typing any
 * of them finds it. Unicode-aware via `\p{L}` and `\p{N}` because a name in a
 * non-Latin script is not a rare case, and a tokeniser that silently drops it
 * would make the search quietly useless for whoever has one.
 */
export function tokenise(text: string): string[] {
    return text
        .toLowerCase()
        .split(/[^\p{L}\p{N}]+/u)
        .filter((token) => token !== '');
}

export function buildIndex(documents: readonly Indexable[]): SearchIndex {
    const postings = new Map<string, Map<string, number>>();

    for (const { id, fields } of documents) {
        for (const [field, text] of Object.entries(fields)) {
            const weight = FIELD_WEIGHTS[field as SearchField];

            for (const token of tokenise(text ?? '')) {
                let entry = postings.get(token);

                if (!entry) {
                    entry = new Map<string, number>();
                    postings.set(token, entry);
                }

                entry.set(id, (entry.get(id) ?? 0) + weight);
            }
        }
    }

    return { postings, size: documents.length };
}

export const EMPTY_INDEX: SearchIndex = { postings: new Map(), size: 0 };

/**
 * Every document matching one query token by prefix, with its score.
 *
 * This walks every distinct token in the index. That is a linear scan and it
 * looks wrong, so it is worth saying why it stays: at ten thousand secrets the
 * index holds a few tens of thousands of distinct tokens, and a scan of that is
 * well under a millisecond — measured, not assumed, in
 * docs/06-testing-and-ci.md. A trie would be faster and would be a hundred more
 * lines of code that nobody could check by eye. If the measurement changes, so
 * should this.
 */
function scoreToken(index: SearchIndex, token: string): Map<string, number> {
    const scores = new Map<string, number>();

    for (const [indexed, postings] of index.postings) {
        if (!indexed.startsWith(token)) {
            continue;
        }

        /*
         | An exact token scores double a prefix hit, so searching "aws" puts
         | the item actually called "aws" above the one called
         | "aws-backup-role" — the shorter, exact match is nearly always the
         | one that was meant.
         */
        const multiplier = indexed === token ? 2 : 1;

        for (const [id, weight] of postings) {
            scores.set(id, (scores.get(id) ?? 0) + weight * multiplier);
        }
    }

    return scores;
}

/**
 * Ranks documents matching every token in the query.
 *
 * AND rather than OR: typing a second word should narrow, which is what people
 * expect and what makes a long query useful. Each query token matches by
 * prefix, so `prod` finds `production` while it is still being typed — the
 * common case is someone halfway through a word.
 */
export function search(index: SearchIndex, query: string, limit = 50): SearchHit[] {
    const tokens = tokenise(query);

    if (tokens.length === 0) {
        return [];
    }

    const matches = scoreToken(index, tokens[0] ?? '');

    // Intersect: every token must be present somewhere in the document.
    for (const token of tokens.slice(1)) {
        const forToken = scoreToken(index, token);

        for (const [id, carried] of matches) {
            const score = forToken.get(id);

            if (score === undefined) {
                matches.delete(id);
            } else {
                matches.set(id, carried + score);
            }
        }
    }

    return (
        [...matches]
            .map(([id, score]) => ({ id, score }))
            // Ties broken by id so the order is stable between keystrokes; a list
            // that reshuffles under the cursor is worse than one ranked slightly
            // differently.
            .sort((a, b) => b.score - a.score || a.id.localeCompare(b.id))
            .slice(0, limit)
    );
}
