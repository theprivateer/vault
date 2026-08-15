/**
 * Length hiding: rounding plaintexts up to bucket sizes before they are sealed.
 *
 * **The leak this closes.** AEAD ciphertext is exactly as long as its plaintext
 * plus a fixed overhead, so the stored length of a payload is the length of the
 * JSON inside it, to the byte. A server that cannot read a secret can still see
 * that one row is 71 bytes and another is 4,200, and length alone is
 * informative: a 40-character random password looks nothing like a recovery
 * note, an SSH private key looks nothing like a card number, and watching a
 * length change on update tells you a password was rotated to something
 * shorter. This is the "ciphertext lengths" entry under accepted leakage in
 * docs/02-threat-model.md, and padding is what moves it from "exact" to
 * "which of a handful of buckets".
 *
 * **What it does not close.** Bucketing reveals the bucket. An item in the
 * 4 KiB bucket is still visibly larger than one in the 64-byte bucket, and a
 * determined observer learns roughly that much. Padding every payload to a
 * single fixed size would close it completely and would also make a 60-byte
 * password cost the same as a document; the buckets are the compromise, and the
 * compromise is stated rather than glossed.
 *
 * **The scheme** is ISO/IEC 7816-4: append a single `0x80` byte, then `0x00` to
 * the bucket boundary. It is unambiguous for any input — including one that
 * already ends in `0x00` or `0x80` — because the delimiter is always added, so
 * there is always exactly one `0x80` to find scanning back over the zero run.
 * A length prefix would work too and would be one byte cheaper; the delimiter
 * is preferred because unpadding it cannot be made to read past the end of the
 * buffer, which a corrupted length prefix can.
 *
 * Padding is applied *inside* the AEAD, so the padding bytes are covered by the
 * authentication tag. Padding outside would let anyone reshape the stored
 * length at will, which is the leak this is meant to remove.
 */
import { MalformedEnvelopeError } from './errors';

/** ISO/IEC 7816-4 delimiter: marks the last byte of real plaintext. */
const DELIMITER = 0x80;

/**
 * The smallest bucket. Below this the padding costs more, proportionally, than
 * it hides — and nothing meaningful is a payload of under 64 bytes, since even
 * an empty item carries its JSON keys.
 */
export const MIN_BUCKET = 64;

/**
 * Powers of two to 4 KiB, then a fixed stride.
 *
 * Doubling is the right shape for small payloads: it keeps the worst-case waste
 * at just under 50% while collapsing the whole realistic range of credentials
 * into five buckets. Above 4 KiB it stops doubling, because an 8 KiB payload
 * padded to 16 KiB is real storage spent to distinguish "large" from "large",
 * and by then the item is a document whose size is not a secret worth this
 * price. Compare Padmé, which makes the same trade with a smoother curve; the
 * powers of two are chosen here for being obvious from the stored numbers,
 * which matters for a project meant to be read.
 */
export const MAX_DOUBLING_BUCKET = 4096;

/**
 * Returns the bucket a plaintext of `length` bytes pads into.
 *
 * Exported because the benchmark and the tests both need to state expected
 * stored sizes, and recomputing the rule in three places is how the three
 * quietly stop agreeing.
 */
export function bucketFor(length: number): number {
    if (length >= MAX_DOUBLING_BUCKET) {
        return Math.ceil(length / MAX_DOUBLING_BUCKET) * MAX_DOUBLING_BUCKET;
    }

    let bucket = MIN_BUCKET;

    while (bucket < length) {
        bucket *= 2;
    }

    return bucket;
}

/**
 * Pads a plaintext up to its bucket size.
 *
 * The delimiter is always written, so a plaintext that already lands exactly on
 * a boundary is pushed into the next bucket rather than left ambiguous. That
 * costs one bucket in a rare case and buys an unpadding routine with no special
 * cases in it.
 */
export function pad(plaintext: Uint8Array): Uint8Array {
    const padded = new Uint8Array(bucketFor(plaintext.length + 1));

    padded.set(plaintext);
    padded[plaintext.length] = DELIMITER;

    return padded;
}

/**
 * Strips the padding, or refuses.
 *
 * Reached only after the AEAD tag has verified, so a malformed structure here
 * means a bug in a writer rather than an attack — an attacker cannot produce
 * padding this function will see without also producing a valid tag. It is
 * still an error rather than a best-effort recovery, because guessing at the
 * boundary of a decrypted secret is precisely the class of leniency that this
 * project exists to avoid.
 */
export function unpad(padded: Uint8Array): Uint8Array {
    let index = padded.length - 1;

    while (index >= 0 && padded[index] === 0x00) {
        index--;
    }

    if (index < 0 || padded[index] !== DELIMITER) {
        throw new MalformedEnvelopeError(
            'Decrypted payload has no padding delimiter. It was written by something that does not ' +
                'pad, or its declared payload version is wrong.',
        );
    }

    return padded.slice(0, index);
}
