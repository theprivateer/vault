/**
 * A deterministic picture of a fingerprint.
 *
 * People are poor at comparing 24 characters of base32 and good at noticing that
 * a shape changed. So an identity gets a visual hash beside its fingerprint: the
 * same keys always draw the same picture, and a substituted key draws a
 * different one, which is a difference the eye catches without being asked to.
 *
 * **It is an aid, not the check.** The grid encodes 56 bits, and a symmetric
 * grid is a birthday problem, so an attacker willing to grind roughly 2^28
 * keypairs — minutes of work — could produce a different identity that draws the
 * same picture. That is why every place this appears also shows the characters,
 * and why the wording asks the user to compare *those* when it matters. A
 * limitation stated is worth more than a limitation designed around badly.
 */
import { hash256 } from '@/crypto/primitives';

/** Odd, so the grid has a true centre column to mirror about. */
export const IDENTICON_SIZE = 7;

const MIRROR_AXIS = (IDENTICON_SIZE - 1) / 2;

/** Filled, and whether it is drawn in the accent tone or the foreground. */
export interface IdenticonCell {
    x: number;
    y: number;
    accent: boolean;
}

/**
 * The filled cells of the grid, left-to-right then top-to-bottom.
 *
 * Only the left half and the centre column are derived; the right half mirrors
 * them. Symmetry is what makes the result read as a single shape rather than
 * noise, which is the entire reason it is easier to compare than the hex.
 *
 * Hashed rather than read straight off the fingerprint. The fingerprint is
 * already uniform, so slicing it would be sound — but hashing means every bit of
 * it feeds the picture, so this stays correct if a shorter or structured
 * identifier is ever passed in.
 */
export function identicon(fingerprint: Uint8Array): IdenticonCell[] {
    const bits = hash256(fingerprint);
    const cells: IdenticonCell[] = [];

    let index = 0;

    for (let y = 0; y < IDENTICON_SIZE; y++) {
        for (let x = 0; x <= MIRROR_AXIS; x++) {
            const filled = bitAt(bits, index++);
            const accent = bitAt(bits, index++);

            if (!filled) {
                continue;
            }

            cells.push({ x, y, accent });

            if (x !== MIRROR_AXIS) {
                cells.push({ x: IDENTICON_SIZE - 1 - x, y, accent });
            }
        }
    }

    return cells;
}

function bitAt(bytes: Uint8Array, index: number): boolean {
    // Non-null: 7×4×2 = 56 bits are read from a 32-byte hash.
    return ((bytes[index >> 3]! >> (index & 7)) & 1) === 1;
}
