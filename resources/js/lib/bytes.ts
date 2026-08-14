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

export function encodeUtf8(value: string): Uint8Array {
    return new TextEncoder().encode(value);
}

export function decodeUtf8(bytes: Uint8Array): string {
    return new TextDecoder().decode(bytes);
}
