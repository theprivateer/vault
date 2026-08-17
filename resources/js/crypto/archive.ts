/**
 * The export archive: one file, one passphrase, no server.
 *
 *   ┌──────────┬─────┬─────┬────────┬────────┬────────┬──────────┬──────────┬──────────┐
 *   │ magic    │ ver │ kdf │ m      │ t      │ p      │ salt     │ uuid     │ envelope │
 *   │ 8 bytes  │  1  │  1  │ 4 (BE) │ 4 (BE) │ 4 (BE) │ 16 bytes │ 36 ASCII │ variable │
 *   └──────────┴─────┴─────┴────────┴────────┴────────┴──────────┴──────────┴──────────┘
 *
 * Everything a reader is not carrying in their head is in that header. That is
 * the whole design brief: an archive exists for the day this application is gone
 * — the server switched off, the project abandoned, the operator no longer
 * trusted — and a format whose parameters live only in the code that wrote it is
 * a format that dies with the code. A stranger with this comment and a hex
 * editor can derive the key.
 *
 * **The UUID is ASCII rather than 16 packed bytes** for the same reason. It
 * costs twenty bytes and makes the one identifying field in the header legible
 * in a dump without a tool.
 *
 * The body is an ordinary envelope: XChaCha20-Poly1305, a 24-byte random nonce,
 * a 16-byte tag, associated data naming the archive and its version. Truncate
 * it, and the tag fails.
 *
 * **The header is bound through the key, not through the associated data**, and
 * that is a deliberate choice between two workable designs. Every byte of the
 * header is the HKDF salt, so editing any of it — magic, version, KDF
 * identifier, cost parameters, salt, UUID — produces a different key and a
 * decryption that fails. Doing it in the AAD instead would have bound the same
 * bytes, at the cost of widening `seal`'s parameter type for one caller, and
 * would have needed somebody to remember to extend the binding every time the
 * header grew a field. This way a field added in version 2 is covered on the day
 * it is added, by nobody's diligence.
 *
 * Spec: docs/03-cryptographic-design.md#export-archive
 */
import { open, seal } from './envelope';
import { InvalidParameterError, MalformedEnvelopeError } from './errors';
import {
    KEY_LENGTH,
    STRETCHED_LENGTH,
    concat,
    deriveKey,
    randomBytes,
    utf8ToBytes,
    zeroise,
    type KdfParams,
} from './primitives';
import { argon2id } from '@noble/hashes/argon2.js';

/** `VAULTARC`, so a hex dump says what this is. */
export const ARCHIVE_MAGIC = utf8ToBytes('VAULTARC');

/** The layout above. Bumped if the header changes shape. */
export const ARCHIVE_VERSION = 1;

/** The only KDF this format defines. A second one would take the next number. */
export const KDF_ARGON2ID = 1;

export const ARCHIVE_SALT_LENGTH = 16;

/** Domain separator for the second derivation. Distinct from every other. */
const ARCHIVE_KEY_INFO = 'vault:export:archive:v1';

const UUID_LENGTH = 36;

const VERSION_OFFSET = ARCHIVE_MAGIC.length;
const KDF_OFFSET = VERSION_OFFSET + 1;
const PARAMS_OFFSET = KDF_OFFSET + 1;
const SALT_OFFSET = PARAMS_OFFSET + 12;
const UUID_OFFSET = SALT_OFFSET + ARCHIVE_SALT_LENGTH;

/** Where the envelope starts, and the exact run of bytes bound into the key. */
export const ARCHIVE_HEADER_LENGTH = UUID_OFFSET + UUID_LENGTH;

/**
 * Deliberately harder than a login, and the difference is not an oversight.
 *
 * An account's Argon2id parameters are a compromise with somebody standing at a
 * login form several times a day. An archive is opened once, in a situation that
 * is already unusual, and it is the artefact most likely to be copied onto a USB
 * stick and forgotten in a drawer — offline, unrated, attackable at leisure.
 * Measured at 3.97 s on an Apple M1, against 731 ms for the login parameters
 * (ADR-0003). Paying four seconds once is a good trade where paying four
 * seconds every morning is not.
 *
 * Written into every archive's header rather than assumed, so raising these
 * later leaves every existing archive readable at the parameters it was made
 * with.
 */
export const ARCHIVE_KDF_PARAMS: KdfParams = { m: 256 * 1024, t: 4, p: 1 };

/**
 * The shortest passphrase this will seal an archive under.
 *
 * A length floor rather than a strength score, because `lib/strength.ts` is
 * honest about being a guess and this is the one place where guessing wrong is
 * unrecoverable — the archive is the copy that outlives the account. Twelve
 * characters is a floor and not an endorsement; the page offers a generated
 * passphrase and says plainly that it is the better answer.
 */
export const MIN_PASSPHRASE_LENGTH = 12;

/**
 * The widest cost parameters this will *attempt*.
 *
 * Not a security control — a lowered parameter already fails, because the key
 * is derived from it — but a robustness one, and it was found by a test rather
 * than reasoned about. Flipping one byte of the memory cost turns 256 MiB into
 * four terabytes, and the honest failure for that is a sentence saying the
 * header is implausible. What happened instead was an allocation the runtime
 * refused, several frames after the passphrase was typed, reported as a range
 * error from inside Argon2id.
 *
 * The bounds are deliberately far above anything this build writes, so a future
 * archive made at genuinely higher settings still opens here.
 */
const MAX_MEMORY_KIB = 4 * 1024 * 1024;
const MAX_PASSES = 64;
const MAX_PARALLELISM = 16;

export interface ArchiveHeader {
    version: number;
    kdf: number;
    params: KdfParams;
    salt: Uint8Array;
    uuid: string;
}

function view(bytes: Uint8Array): DataView {
    return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

/**
 * Stretches the passphrase, then binds the result to the header it came with.
 *
 * Two derivations, each doing one job. Argon2id turns a passphrase into key
 * material and is slow on purpose; HKDF is free and is what makes the key
 * depend on every byte of the header. Running the header through Argon2id's own
 * salt parameter instead would have conflated "make this expensive" with "bind
 * this to its context", and left the salt no longer being a salt.
 *
 * `STRETCHED_LENGTH` bytes come out of Argon2id, matching `deriveFromPassword`.
 * An archive has no auth key to split off and uses the first 32 bytes, but
 * deriving a different length would mean the same passphrase and parameters
 * produced different material in two places, and a reader comparing them would
 * have to work out which was intended.
 */
function archiveKey(passphrase: string, header: Uint8Array, params: KdfParams, salt: Uint8Array): Uint8Array {
    const stretched = argon2id(passphrase, salt, {
        m: params.m,
        t: params.t,
        p: params.p,
        dkLen: STRETCHED_LENGTH,
    });

    const key = deriveKey(stretched.slice(0, KEY_LENGTH), header, ARCHIVE_KEY_INFO);
    zeroise(stretched);

    return key;
}

function headerBytes(header: ArchiveHeader): Uint8Array {
    const bytes = new Uint8Array(ARCHIVE_HEADER_LENGTH);

    bytes.set(ARCHIVE_MAGIC, 0);
    bytes[VERSION_OFFSET] = header.version;
    bytes[KDF_OFFSET] = header.kdf;
    view(bytes).setUint32(PARAMS_OFFSET, header.params.m, false);
    view(bytes).setUint32(PARAMS_OFFSET + 4, header.params.t, false);
    view(bytes).setUint32(PARAMS_OFFSET + 8, header.params.p, false);
    bytes.set(header.salt, SALT_OFFSET);
    bytes.set(utf8ToBytes(header.uuid), UUID_OFFSET);

    return bytes;
}

/**
 * Encrypts an archive under a passphrase.
 *
 * `uuid` identifies this archive and nothing else. Binding it stops one
 * archive's body being read inside another's header — a smaller concern than
 * for a database row, and free to close.
 *
 * `params` exists so the cost can be raised without a format change and so the
 * tests can run at a cost that is not four seconds each; every archive records
 * what it was made with. Nothing in the interface passes it, and nothing should
 * offer a way to lower it — a cheaper archive is a weaker one with no
 * compensating benefit, since it is opened once.
 */
export function sealArchive(
    passphrase: string,
    plaintext: Uint8Array,
    uuid: string,
    params: KdfParams = ARCHIVE_KDF_PARAMS,
): Uint8Array {
    if (passphrase.length < MIN_PASSPHRASE_LENGTH) {
        throw new InvalidParameterError(
            `An archive passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters. ` +
                'It is the only thing protecting a file that will outlive this account.',
        );
    }

    const bytes = headerBytes({
        version: ARCHIVE_VERSION,
        kdf: KDF_ARGON2ID,
        params,
        salt: randomBytes(ARCHIVE_SALT_LENGTH),
        uuid,
    });

    const key = archiveKey(passphrase, bytes, params, bytes.slice(SALT_OFFSET, UUID_OFFSET));

    try {
        return concat(
            bytes,
            seal(key, plaintext, { context: 'export.archive', subject: uuid, version: ARCHIVE_VERSION }),
        );
    } finally {
        zeroise(key);
    }
}

/**
 * Reads an archive's header without touching the passphrase.
 *
 * Separate from opening it because the decryptor shows the header first: an
 * archive that identifies itself and states its own cost parameters lets
 * somebody confirm they have the right file before spending several seconds of
 * Argon2id on the wrong one.
 */
export function readArchiveHeader(archive: Uint8Array): ArchiveHeader {
    if (archive.length < ARCHIVE_HEADER_LENGTH) {
        throw new MalformedEnvelopeError(
            `An archive is at least ${ARCHIVE_HEADER_LENGTH} bytes; this one is ${archive.length}.`,
        );
    }

    if (!ARCHIVE_MAGIC.every((byte, index) => archive[index] === byte)) {
        throw new MalformedEnvelopeError('This file does not begin with VAULTARC, so it is not an archive.');
    }

    const version = archive[VERSION_OFFSET]!;
    const kdf = archive[KDF_OFFSET]!;

    if (version !== ARCHIVE_VERSION) {
        throw new MalformedEnvelopeError(
            `This archive is version ${version}; this build reads version ${ARCHIVE_VERSION}.`,
        );
    }

    if (kdf !== KDF_ARGON2ID) {
        throw new MalformedEnvelopeError(`This archive names key derivation ${kdf}, which is not Argon2id.`);
    }

    const numbers = view(archive);
    const params: KdfParams = {
        m: numbers.getUint32(PARAMS_OFFSET, false),
        t: numbers.getUint32(PARAMS_OFFSET + 4, false),
        p: numbers.getUint32(PARAMS_OFFSET + 8, false),
    };

    if (params.m < 8 || params.m > MAX_MEMORY_KIB) {
        throw new MalformedEnvelopeError(
            `This archive asks for ${params.m} KiB of memory, which is not a plausible header. ` +
                'It is corrupt, or it has been edited.',
        );
    }

    if (params.t < 1 || params.t > MAX_PASSES || params.p < 1 || params.p > MAX_PARALLELISM) {
        throw new MalformedEnvelopeError(
            `This archive asks for ${params.t} passes at parallelism ${params.p}, which is not a ` +
                'plausible header. It is corrupt, or it has been edited.',
        );
    }

    return {
        version,
        kdf,
        params,
        salt: archive.slice(SALT_OFFSET, UUID_OFFSET),
        uuid: new TextDecoder().decode(archive.slice(UUID_OFFSET, ARCHIVE_HEADER_LENGTH)),
    };
}

/**
 * Decrypts an archive.
 *
 * Throws on every failure, including a wrong passphrase — which is
 * indistinguishable from a tampered archive here, and surfaces as an integrity
 * failure because that is what the cipher observed. The interface above says
 * "wrong passphrase, or this file has been altered" rather than guessing which.
 */
export function openArchive(passphrase: string, archive: Uint8Array): Uint8Array {
    const header = readArchiveHeader(archive);
    const key = archiveKey(passphrase, archive.slice(0, ARCHIVE_HEADER_LENGTH), header.params, header.salt);

    try {
        return open(key, archive.slice(ARCHIVE_HEADER_LENGTH), {
            context: 'export.archive',
            subject: header.uuid,
            version: header.version,
        });
    } finally {
        zeroise(key);
    }
}
