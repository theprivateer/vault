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

    return join([AAD_PREFIX, context, normalised, String(version)]);
}

/**
 * A file chunk's position within its file, bound into the chunk's own AAD.
 *
 * `chunkCount` is not decoration. Binding the index alone would let a server
 * serve chunks 0..n-2 of an n-chunk file and have every one of them verify —
 * **truncation would be undetectable by the tag** and would fall to the
 * application noticing a short read, which is exactly the kind of check that
 * gets skipped. With the count inside the AAD, a chunk sealed as "3 of 40" only
 * ever opens as "3 of 40".
 *
 * The spec in docs/03 also listed an `is_final` flag. It is not here because it
 * carries no information: `chunkIndex === chunkCount - 1` already determines it,
 * and a second encoding of the same fact is one more thing to get out of step.
 */
export interface ChunkAadParams extends AadParams {
    context: 'file.chunk';
    chunkIndex: number;
    chunkCount: number;
}

/**
 * Builds the associated data for one chunk of a file.
 *
 *   AAD = "vault.v1" ‖ 0x00 ‖ "file.chunk" ‖ 0x00 ‖ uuid ‖ 0x00 ‖ version
 *                    ‖ 0x00 ‖ index ‖ 0x00 ‖ count
 *
 * **Both numbers must come from the manifest, never from the server.** The
 * manifest lives inside `payload_ct`, so a client that has opened the file's
 * payload already knows how many chunks there should be; a client that took the
 * count from the response it is validating would be asking the sender to
 * confirm its own claim.
 */
export function buildChunkAad({
    context,
    subject,
    version,
    chunkIndex,
    chunkCount,
}: ChunkAadParams): Uint8Array {
    if (!Number.isSafeInteger(chunkCount) || chunkCount < 1) {
        throw new InvalidParameterError(`A file must have at least one chunk, received: ${chunkCount}`);
    }

    if (!Number.isSafeInteger(chunkIndex) || chunkIndex < 0 || chunkIndex >= chunkCount) {
        throw new InvalidParameterError(
            `Chunk index ${chunkIndex} is outside a file of ${chunkCount} chunks.`,
        );
    }

    const base = buildAad({ context, subject, version });

    return join([base, String(chunkIndex), String(chunkCount)]);
}

/** NUL-joins the parts. Unambiguous only because no part can contain a NUL. */
function join(parts: ReadonlyArray<string | Uint8Array>): Uint8Array {
    const encoded = parts.map((part) => (typeof part === 'string' ? utf8ToBytes(part) : part));

    const totalLength = encoded.reduce((sum, part) => sum + part.length, 0) + encoded.length - 1;
    const aad = new Uint8Array(totalLength);

    let offset = 0;
    encoded.forEach((part, index) => {
        if (index > 0) {
            aad[offset] = SEPARATOR;
            offset += 1;
        }
        aad.set(part, offset);
        offset += part.length;
    });

    return aad;
}
