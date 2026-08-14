/**
 * UUIDv7 generation.
 *
 * The client generates identifiers rather than the server, because associated
 * data has to bind a ciphertext to its record *before* that record exists — the
 * payload is encrypted in the browser and only then posted. See
 * docs/03-cryptographic-design.md#creating-a-vault.
 *
 * v7 rather than v4 so identifiers sort by creation time, which keeps database
 * indexes well behaved. `crypto.randomUUID()` only produces v4, hence this.
 */

/** RFC 9562 §5.7: 48-bit big-endian timestamp, version, variant, then random. */
export function uuid7(now: number = Date.now()): string {
    const bytes = crypto.getRandomValues(new Uint8Array(16));

    const timestamp = BigInt(now);

    for (let i = 0; i < 6; i++) {
        bytes[i] = Number((timestamp >> BigInt(8 * (5 - i))) & 0xffn);
    }

    // Version 7 in the high nibble of byte 6.
    bytes[6] = (bytes[6]! & 0x0f) | 0x70;

    // RFC 4122 variant in the top two bits of byte 8.
    bytes[8] = (bytes[8]! & 0x3f) | 0x80;

    const hex = [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');

    return [hex.slice(0, 8), hex.slice(8, 12), hex.slice(12, 16), hex.slice(16, 20), hex.slice(20, 32)].join(
        '-',
    );
}
