/**
 * Every failure in the crypto core is an exception. Nothing returns null,
 * undefined or an empty value to signal that decryption failed.
 *
 * This is deliberate and it is the inverse of the bug that motivated the
 * rebuild: the 2017 application caught DecryptException and returned null, so
 * a tampered ciphertext was indistinguishable from an empty secret. See SR3 in
 * docs/02-threat-model.md.
 */

export class CryptoError extends Error {
    constructor(message: string) {
        super(message);
        this.name = new.target.name;
    }
}

/**
 * An AEAD tag did not verify. The ciphertext was modified, truncated, encrypted
 * under a different key, or bound to a different record.
 *
 * This must always surface to the user as a specific, visible error naming the
 * affected record — never as a blank field.
 */
export class IntegrityError extends CryptoError {
    constructor(
        readonly context: string,
        readonly subject: string,
    ) {
        super(
            `Integrity check failed for ${context} on ${subject}. ` +
                'The stored data could not be verified and may have been tampered with.',
        );
    }
}

/**
 * The envelope carries a version or algorithm identifier this build does not
 * implement. Thrown rather than falling back to a default, so a downgrade
 * attempt fails loudly.
 */
export class UnsupportedEnvelopeError extends CryptoError {
    constructor(
        readonly envelopeVersion: number,
        readonly algorithm: number,
    ) {
        super(
            `Unsupported envelope (version ${envelopeVersion}, algorithm ${algorithm}). ` +
                'This data was written by a newer version of the application.',
        );
    }
}

/** The envelope is too short to be well formed, or is structurally invalid. */
export class MalformedEnvelopeError extends CryptoError {}

/** No key in the current hierarchy can decrypt the requested item. */
export class KeyUnavailableError extends CryptoError {}

/** A caller passed a value the crypto core refuses to operate on. */
export class InvalidParameterError extends CryptoError {}
