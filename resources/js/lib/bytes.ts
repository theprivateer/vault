/**
 * Base64 at the transport boundary.
 *
 * The API speaks base64 because JSON cannot carry bytes; the crypto core speaks
 * Uint8Array. Conversion happens here and nowhere else, so there is one place
 * to check when something arrives the wrong shape.
 */
export function toBase64(bytes: Uint8Array): string {
    let binary = '';

    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }

    return btoa(binary);
}

export function fromBase64(value: string): Uint8Array {
    const binary = atob(value);
    const bytes = new Uint8Array(binary.length);

    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }

    return bytes;
}

/**
 * Hex, for fingerprints.
 *
 * Fingerprints travel as hex rather than base64 because they are compared by
 * eye and quoted in grants, where a single canonical spelling matters more than
 * a third fewer characters — base64 has variants, and hex has one.
 */
export function toHex(bytes: Uint8Array): string {
    let hex = '';

    for (const byte of bytes) {
        hex += byte.toString(16).padStart(2, '0');
    }

    return hex;
}

export function fromHex(value: string): Uint8Array {
    if (value.length % 2 !== 0 || !/^[0-9a-f]*$/.test(value)) {
        throw new Error(`Expected lowercase hex with an even length, received: ${value}`);
    }

    const bytes = new Uint8Array(value.length / 2);

    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16);
    }

    return bytes;
}

export function encodeUtf8(value: string): Uint8Array {
    return new TextEncoder().encode(value);
}

export function decodeUtf8(bytes: Uint8Array): string {
    return new TextDecoder().decode(bytes);
}
