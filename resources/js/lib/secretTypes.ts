/**
 * What each kind of secret is made of.
 *
 * One declarative table, read by the form, the row renderer, the share view, the
 * search indexer and the history diff. The alternative — a bespoke form block
 * and a bespoke renderer per type — would put twelve separate paths from a
 * decrypted field to the DOM, each its own place to get masking or indexing
 * wrong. Here those are properties of a row in a table, which means they can be
 * asserted as a table too (`secretTypes.test.ts`).
 *
 * **The type never reaches the server.** It lives inside `payload_ct` like
 * everything else, because a `type` column would say which rows are SSH keys and
 * which are one-time-password seeds — a targeting signal for free. See the
 * comment on the `secrets` table.
 *
 * **What the padding does and does not hide, measured rather than assumed.**
 * Field sets differ per type, so it is fair to ask whether the padding bucket now
 * hints at which type an item is. Serialising a realistic item of each type and
 * bucketing it says: mostly no, and never for long.
 *
 * With an empty note, the 128-byte bucket holds seven candidate types and the
 * 256-byte bucket four. Only `server` is ever alone in a bucket, and only when
 * fully populated with no note at all — 100 characters of notes puts it back with
 * four others, and 200 collapses all twelve types into one bucket. The dominant
 * term in a payload's size is its *content*, overwhelmingly the note, not the
 * shape of its type.
 *
 * **`buildPayload` drops empty fields, and that is the privacy-preserving
 * choice — the opposite of what it looks like.** Writing every key of a type,
 * empty ones included, would make items of one type a uniform size. That sounds
 * like the defensive option and is the wrong way round: uniformity *tightens*
 * each type's size range, and tight ranges that differ from each other are what
 * makes types separable. Dropping empties lets a sparsely-filled address sit in
 * the same bucket as a text item, which is exactly the overlap that hides both.
 * Measured: dropping gives the 128 bucket eleven candidate types out of twelve;
 * writing every key gives it eight.
 *
 * The residue is in docs/02 § Accepted leakage.
 */

/** The slug stored in the payload. Stable — changing one orphans existing rows. */
export type SecretType =
    | 'password'
    | 'text'
    | 'url'
    | 'email'
    | 'note'
    | 'key'
    | 'otp'
    | 'card'
    | 'address'
    | 'lockbox'
    | 'server'
    | 'api';

/**
 * How a field is entered and rendered.
 *
 * `password` is `secret` plus the strength meter and the generator, which are
 * deliberately not offered on every masked field: a card number has no strength
 * to measure and generating one would be nonsense.
 */
export type FieldControl =
    'text' | 'secret' | 'password' | 'textarea' | 'url' | 'email' | 'number' | 'totp' | 'lockbox';

/**
 * Every key a payload may carry, across all types.
 *
 * `linkedLockboxUuid` is the one that is not a payload key at all — it is a
 * column, because the server enforces that both ends of a link live in the same
 * vault and needs to see the edge to do it. The form treats it like any other
 * field and `save()` separates it again; that is why this union covers it.
 */
export type SecretFieldKey =
    | 'value'
    | 'username'
    | 'notes'
    | 'url'
    | 'totp'
    | 'cardholder'
    | 'cardNumber'
    | 'cardExpiry'
    | 'cardCvv'
    | 'street'
    | 'city'
    | 'region'
    | 'postcode'
    | 'country'
    | 'host'
    | 'port'
    | 'expires'
    | 'scope'
    | 'linkedLockboxUuid';

export interface SecretField {
    key: SecretFieldKey;
    label: string;
    control: FieldControl;
    /**
     * Masked until deliberately revealed, and the target of a copy button.
     *
     * An interface courtesy against shoulder-surfing, never a boundary: by the
     * time a field reaches a component it has already been decrypted. Marking
     * one has real consequences all the same — it decides what the share view
     * hides behind a click and what the clipboard clears after ninety seconds.
     */
    sensitive?: boolean;
    /**
     * Whether this field enters the search index.
     *
     * **Defaults to false, and that default is the point.** The standing rule is
     * that identifiers and locators are searchable and anything that
     * authenticates is not — so a username, a hostname, an email address, a
     * cardholder or a city opts in, and a password, a token, a card number, a
     * CVV or a one-time-password seed cannot be made searchable by someone
     * adding a field without thinking about it.
     */
    indexable?: boolean;
    placeholder?: string;
    hint?: string;
}

export interface SecretTypeSpec {
    /** What the type is called on screen, and what the search index tokenises. */
    label: string;
    /** A sentence for the type picker, so the choice is not a guessing game. */
    description: string;
    fields: SecretField[];
}

/**
 * Carried by every type, appended after its own fields.
 *
 * Notes stays universal on purpose: it is the escape hatch that stops somebody
 * forcing an address into a card because there was nowhere else to put it. A
 * typed field set is only an improvement while there is somewhere to go when it
 * does not fit.
 */
const NOTES: SecretField = { key: 'notes', label: 'notes', control: 'textarea', indexable: true };

/** `url` where it means "where I use this", rather than "this item is a link". */
const URL_FIELD: SecretField = { key: 'url', label: 'url', control: 'url', indexable: true };

/**
 * The one-time-password seed.
 *
 * Offered on the login-shaped types as well as on `otp` itself. A login with a
 * second factor is the case this field exists for, and confining the seed to a
 * standalone type would both split one credential across two items and orphan
 * the `totp` already inside existing password payloads.
 */
const TOTP: SecretField = {
    key: 'totp',
    label: 'one-time password seed',
    control: 'totp',
    sensitive: true,
    placeholder: 'base32 seed, or paste a whole otpauth:// link',
    hint: 'Stays inside the encrypted payload, like everything else. Paste the setup link a site gives you when you cannot scan its QR code.',
};

export const SECRET_TYPES: Record<SecretType, SecretTypeSpec> = {
    password: {
        label: 'password',
        description: 'A sign-in: who you are, what proves it, and where you use it.',
        fields: [
            { key: 'username', label: 'username', control: 'text', indexable: true },
            { key: 'value', label: 'password', control: 'password', sensitive: true },
            URL_FIELD,
            TOTP,
        ],
    },
    text: {
        label: 'text',
        description: 'A single line of anything. No password tools.',
        fields: [{ key: 'value', label: 'value', control: 'text' }],
    },
    url: {
        label: 'url',
        description: 'A link worth keeping, with nothing secret about it.',
        fields: [{ key: 'value', label: 'url', control: 'url', indexable: true }],
    },
    email: {
        label: 'email',
        description: 'An email address on its own. Use a password item for a mailbox you sign in to.',
        fields: [{ key: 'value', label: 'email address', control: 'email', indexable: true }],
    },
    note: {
        label: 'note',
        description: 'Free text over several lines, hidden until you ask for it.',
        fields: [{ key: 'value', label: 'note', control: 'textarea', sensitive: true }],
    },
    key: {
        label: 'key',
        description: 'A private key, certificate or other multi-line credential.',
        fields: [{ key: 'value', label: 'key', control: 'textarea', sensitive: true }],
    },
    otp: {
        label: 'one-time password',
        description: 'A standalone authenticator seed, where the password lives elsewhere.',
        fields: [TOTP],
    },
    card: {
        label: 'card',
        description: 'A payment card. The number and security code are hidden; the name on it is not.',
        fields: [
            { key: 'cardholder', label: 'cardholder name', control: 'text', indexable: true },
            { key: 'cardNumber', label: 'number', control: 'secret', sensitive: true },
            { key: 'cardExpiry', label: 'expiry', control: 'text', placeholder: 'MM/YY' },
            { key: 'cardCvv', label: 'security code', control: 'secret', sensitive: true },
        ],
    },
    address: {
        label: 'address',
        description: 'A postal address.',
        fields: [
            { key: 'street', label: 'street', control: 'text' },
            { key: 'city', label: 'city / town / suburb', control: 'text', indexable: true },
            { key: 'region', label: 'state / province', control: 'text' },
            { key: 'postcode', label: 'zip / postal code', control: 'text' },
            { key: 'country', label: 'country', control: 'text', indexable: true },
        ],
    },
    lockbox: {
        label: 'lockbox',
        description: 'Points at another lockbox in this vault, as a value in its own right.',
        fields: [{ key: 'linkedLockboxUuid', label: 'lockbox', control: 'lockbox' }],
    },
    server: {
        label: 'server',
        description: 'A machine you sign in to. Link a key item beside it if you use one.',
        fields: [
            { key: 'host', label: 'host', control: 'text', indexable: true },
            { key: 'port', label: 'port', control: 'number' },
            { key: 'username', label: 'username', control: 'text', indexable: true },
            { key: 'value', label: 'password', control: 'password', sensitive: true },
            URL_FIELD,
            TOTP,
        ],
    },
    api: {
        label: 'api credential',
        description: 'A token or key issued to you by a service. Usually expires.',
        fields: [
            { key: 'value', label: 'token', control: 'secret', sensitive: true },
            { key: 'expires', label: 'expires on', control: 'text', placeholder: 'YYYY-MM-DD' },
            { key: 'scope', label: 'scope', control: 'text' },
            URL_FIELD,
        ],
    },
};

/** The picker's order: most-used first, then the structured ones. */
export const SECRET_TYPE_ORDER: SecretType[] = [
    'password',
    'text',
    'url',
    'email',
    'note',
    'key',
    'otp',
    'card',
    'address',
    'server',
    'api',
    'lockbox',
];

const KNOWN = new Set<string>(SECRET_TYPE_ORDER);

/**
 * Whether a string names a type this build knows.
 *
 * A payload written by a future build can name a type this one has never heard
 * of. That must render as an item with unrecognised fields, never as a crash and
 * never as a silent reinterpretation under some default schema — which would
 * show a token in a field labelled "note" and mask nothing.
 */
export function isKnownType(type: string): type is SecretType {
    return KNOWN.has(type);
}

/** The fields a type shows, in order, with notes last. */
export function fieldsFor(type: string): SecretField[] {
    return isKnownType(type) ? [...SECRET_TYPES[type].fields, NOTES] : [NOTES];
}

export function labelFor(type: string): string {
    return isKnownType(type) ? SECRET_TYPES[type].label : type;
}

/** Whether a type shows a given field at all. */
export function hasField(type: string, key: SecretFieldKey): boolean {
    return fieldsFor(type).some((field) => field.key === key);
}

/**
 * Every field key any type can carry, for the callers that need a closed set.
 *
 * The history diff walks this rather than the union of two payloads' keys: a
 * payload from a future build could carry a key this one knows nothing about,
 * and rendering an unknown key's contents into the page unlabelled is how a diff
 * view becomes the place an unexpected value gets displayed.
 */
export const ALL_FIELD_KEYS: SecretFieldKey[] = [
    ...new Set(SECRET_TYPE_ORDER.flatMap((type) => fieldsFor(type).map((field) => field.key))),
];

/** Field keys whose contents may enter the search index, across all types. */
export const INDEXABLE_FIELD_KEYS: SecretFieldKey[] = [
    ...new Set(
        SECRET_TYPE_ORDER.flatMap((type) =>
            fieldsFor(type)
                .filter((field) => field.indexable === true)
                .map((field) => field.key),
        ),
    ),
];

/** Keys that are never rendered as a field: structure, not content. */
const NOT_A_FIELD = new Set(['type', 'key', 'paranoid', 'linkedLockboxUuid']);

/**
 * Reads one field out of a payload as a string.
 *
 * Every schema-driven caller goes through this, because the field list is data
 * and so the key is a `string` at the point of use. Anything that is not a
 * string reads as empty rather than being coerced: a payload from elsewhere
 * could hold a number, an object or a null under a key this build expects to
 * render, and `String(value)` would put `[object Object]` on the page.
 */
export function readField(payload: Readonly<Record<string, unknown>>, key: string): string {
    const value = payload[key];

    return typeof value === 'string' ? value : '';
}

/**
 * Payload entries this build's schema has nowhere to put.
 *
 * Two ways an item gets one, and both are real. A payload written by a later
 * build can carry a key this one has never heard of. And an item saved *before*
 * its type gained fields still holds what it had then — every `card` created
 * while cards were a single `value` box is exactly that.
 *
 * Neither may quietly vanish from the page. Content that was decrypted and then
 * not rendered is indistinguishable, to the person looking at it, from content
 * that was lost — and if they then save the item, an editor that dropped what it
 * could not display would make that true. So these are shown, labelled by their
 * raw key, and marked sensitive: a field this build cannot identify is one it
 * cannot judge safe to put on screen in the clear.
 */
export function unmappedFields(
    payload: { type: string } & Record<string, unknown>,
): { field: SecretField; value: string }[] {
    const placed = new Set(fieldsFor(payload.type).map((field) => field.key as string));

    return Object.entries(payload).flatMap(([key, value]) => {
        if (placed.has(key) || NOT_A_FIELD.has(key) || typeof value !== 'string' || value === '') {
            return [];
        }

        return [
            {
                field: {
                    key: key as SecretFieldKey,
                    label: key,
                    control: 'text' as const,
                    sensitive: true,
                },
                value,
            },
        ];
    });
}

/**
 * Assembles the payload a save will seal.
 *
 * Here rather than inline in the form because two of its three rules are
 * security decisions rather than plumbing, and a decision that lives inside a
 * component template is one nothing can assert.
 *
 * 1. **Only the fields the type shows.** Switch a card to a note and its number
 *    goes, rather than lingering in the ciphertext where nothing will ever
 *    display it again — invisible content that is still content.
 * 2. **Only the fields with something in them.** A password item carrying
 *    `totp: ''` would make every row look as though it had a one-time code, and
 *    dropping empties is also what keeps types overlapping in the size buckets;
 *    see the note at the top of this file, which explains why the uniform
 *    alternative is worse.
 * 3. **Anything unplaced is carried through untouched.** An editor that dropped
 *    what it could not display would turn "we cannot show this" into "this is
 *    gone", silently, on the first save.
 */
export function buildPayload(input: {
    type: string;
    key: string;
    fields: Readonly<Record<string, string>>;
    paranoid: boolean;
    unknown: Readonly<Record<string, string>>;
}): { type: string; key: string; value: string; notes: string } & Record<string, unknown> {
    const shown = new Set(fieldsFor(input.type).map((field) => field.key as string));

    return {
        type: input.type,
        key: input.key,
        // `value` and `notes` are always present: every payload this application
        // has ever written carries them, and a reader may assume it.
        value: '',
        notes: '',
        ...input.unknown,
        ...Object.fromEntries(
            Object.entries(input.fields).filter(
                ([name, value]) => shown.has(name) && name !== 'linkedLockboxUuid' && value !== '',
            ),
        ),
        ...(input.paranoid ? { paranoid: true } : {}),
    };
}

/**
 * The searchable view of a decrypted secret.
 *
 * One function, called by both indexers — the vault-wide one behind the command
 * palette and the per-lockbox filter box. Two callers building this shape by
 * hand is how a field ends up searchable in one place and not the other, and how
 * a credential ends up indexed in neither place on purpose and one place by
 * accident.
 *
 * Takes a structural type rather than `SecretPayload` so that this module stays
 * the thing `items.ts` depends on and not the other way round.
 */
export function searchFieldsFor(
    payload: Readonly<Record<string, unknown>> & { type: string; key: string },
    location = '',
): Partial<Record<'name' | 'location' | 'identifier' | 'url' | 'type' | 'notes', string>> {
    const identifiers = fieldsFor(payload.type)
        .filter((field) => field.indexable === true && field.key !== 'notes' && field.key !== 'url')
        .map((field) => readField(payload, field.key))
        .filter((value) => value !== '');

    return {
        name: payload.key,
        location,
        identifier: identifiers.join(' '),
        url: readField(payload, 'url'),
        // The label, not the slug: `api` is what is stored and "api credential"
        // is what somebody types into the search box.
        type: labelFor(payload.type),
        notes: readField(payload, 'notes'),
    };
}

/**
 * Whether a field is masked, for a given type.
 *
 * Asked per type rather than per key because the same key is not always the same
 * kind of thing: `value` is a password on a login and a plain string on a text
 * item. Anything a known type does not declare is treated as sensitive, so an
 * unrecognised field errs towards hidden.
 */
export function isSensitive(type: string, key: SecretFieldKey): boolean {
    const field = fieldsFor(type).find((candidate) => candidate.key === key);

    return field ? field.sensitive === true : true;
}
