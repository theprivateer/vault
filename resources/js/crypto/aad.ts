/**
 * Canonical associated-data construction.
 *
 * Every seal() in this codebase binds its ciphertext to the record and field it
 * belongs to. Without that binding a malicious server can take the ciphertext of
 * a low-value secret and write it over a high-value one, or swap a viewer's
 * wrapped vault key for an owner's, and the client decrypts it happily. With it,
 * the AEAD tag check fails and the client reports a specific integrity error.
 *
 * This is SR4 in docs/02-threat-model.md. It is a few lines of code and it
 * closes an entire attack class, so it lives in one tested place rather than
 * being reconstructed at each call site.
 *
 *   AAD = "vault.v1" ‖ 0x00 ‖ context ‖ 0x00 ‖ subject ‖ 0x00 ‖ version
 */
import { InvalidParameterError } from './errors';
import { utf8ToBytes } from './primitives';

/** Domain separator. Bumped only if the AAD structure itself changes. */
const AAD_PREFIX = 'vault.v1';

const SEPARATOR = 0x00;

/**
 * The complete set of things that get encrypted, each with its own context
 * string. A closed union rather than a free string: a typo in a context would
 * silently create a second, incompatible encryption domain, and the failure
 * would only show up when something could not be decrypted later.
 */
export const AAD_CONTEXTS = [
    'vault.payload',
    'lockbox.payload',
    'secret.payload',
    'secret.version.payload',
    'file.payload',
    'file.chunk',
    'item.key',
    'vault.membership.key',
    'user.userkey',
    'user.privkey.x25519',
    'user.privkey.ed25519',
    'user.pins',
    'sharelink.payload',
] as const;

export type AadContext = (typeof AAD_CONTEXTS)[number];

export interface AadParams {
    /** What is being encrypted. */
    context: AadContext;
    /** UUID of the record the ciphertext belongs to. */
    subject: string;
    /** Schema version of the plaintext inside. */
    version: number;
}

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/**
 * Builds the associated data for a record.
 *
 * The NUL separators are only unambiguous because no field can contain a NUL:
 * the context comes from a closed set, the subject is validated as a UUID, and
 * the version is a decimal integer. Those validations are what make the
 * encoding injective, so they are enforced rather than assumed — otherwise a
 * crafted subject could produce the same AAD as a different record.
 */
export function buildAad({ context, subject, version }: AadParams): Uint8Array {
    if (!AAD_CONTEXTS.includes(context)) {
        throw new InvalidParameterError(`Unknown AAD context: ${context}`);
    }

    const normalised = subject.toLowerCase();

    if (!UUID_PATTERN.test(normalised)) {
        throw new InvalidParameterError(
            `AAD subject must be a UUID, received: ${subject}. ` +
                'Binding to an unvalidated identifier would make the encoding ambiguous.',
        );
    }

    if (!Number.isSafeInteger(version) || version < 0) {
        throw new InvalidParameterError(`AAD version must be a non-negative integer, received: ${version}`);
    }

    const parts = [AAD_PREFIX, context, normalised, String(version)].map(utf8ToBytes);

    const totalLength = parts.reduce((sum, part) => sum + part.length, 0) + parts.length - 1;
    const aad = new Uint8Array(totalLength);

    let offset = 0;
    parts.forEach((part, index) => {
        if (index > 0) {
            aad[offset] = SEPARATOR;
            offset += 1;
        }
        aad.set(part, offset);
        offset += part.length;
    });

    return aad;
}
