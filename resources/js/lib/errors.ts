/**
 * Turning a caught error into something worth reading.
 *
 * There is a specific failure this exists to prevent, and it has already
 * happened twice in this project: a `catch` that reports "something went wrong"
 * makes an environment problem indistinguishable from a cryptographic one. With
 * `no-console` enforced across resources/js — deliberately, so nothing
 * downstream of a decrypt can be logged — that generic sentence is genuinely
 * all anybody gets. A whole afternoon disappears into a message that was never
 * true in the first place.
 *
 * So: an error that knows what it is says so, and an error that does not is
 * reported with its type and message rather than replaced by a guess.
 */
import { CryptoError } from '@/crypto/errors';

/**
 * @param fallback What the operation was trying to do, as a sentence. Used as
 *   the lead-in, never as a replacement for what actually happened.
 */
export function describeError(cause: unknown, fallback: string): string {
    /*
     | Crypto errors are written for the person reading them: an integrity
     | failure names the record, and an unavailable Worker says what to do about
     | it. Wrapping them in a summary would only bury that.
     */
    if (cause instanceof CryptoError) {
        return cause.message;
    }

    /*
     | Anything else is unexpected, so the type is often the whole diagnosis —
     | a SecurityError means the CSP, a TypeError from fetch means the network.
     | Safe to show: errors crossing the Worker boundary have already had their
     | messages reduced to a generic string by serialiseError(), so nothing that
     | touched a payload can reach this line.
     */
    if (cause instanceof Error && cause.message !== '') {
        return `${fallback} (${cause.name}: ${cause.message})`;
    }

    return fallback;
}
