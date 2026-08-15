import { describe, expect, it } from 'vitest';

import { MalformedEnvelopeError } from './errors';
import { bucketFor, MAX_DOUBLING_BUCKET, MIN_BUCKET, pad, unpad } from './padding';

const bytes = (length: number, fill = 0x41) => new Uint8Array(length).fill(fill);

describe('buckets', () => {
    it('rounds everything small up to the minimum', () => {
        for (const length of [0, 1, 17, MIN_BUCKET]) {
            expect(bucketFor(length)).toBe(MIN_BUCKET);
        }
    });

    it('doubles up to the ceiling', () => {
        expect(bucketFor(MIN_BUCKET + 1)).toBe(128);
        expect(bucketFor(129)).toBe(256);
        expect(bucketFor(2049)).toBe(MAX_DOUBLING_BUCKET);
        expect(bucketFor(MAX_DOUBLING_BUCKET - 1)).toBe(MAX_DOUBLING_BUCKET);
    });

    it('switches to a fixed stride above the ceiling', () => {
        expect(bucketFor(MAX_DOUBLING_BUCKET)).toBe(MAX_DOUBLING_BUCKET);
        expect(bucketFor(MAX_DOUBLING_BUCKET + 1)).toBe(2 * MAX_DOUBLING_BUCKET);
        expect(bucketFor(3 * MAX_DOUBLING_BUCKET)).toBe(3 * MAX_DOUBLING_BUCKET);
    });

    it('never returns less than it was given', () => {
        for (let length = 0; length < 600; length++) {
            expect(bucketFor(length)).toBeGreaterThanOrEqual(length);
        }
    });
});

describe('padding', () => {
    it('pads to a bucket boundary', () => {
        expect(pad(bytes(10)).length).toBe(MIN_BUCKET);
        expect(pad(bytes(100)).length).toBe(128);
        expect(pad(bytes(5000)).length).toBe(2 * MAX_DOUBLING_BUCKET);
    });

    /**
     * The property that makes bucketing worth doing: two plaintexts of
     * different length must become indistinguishable by length.
     */
    it('collapses a range of lengths onto one size', () => {
        const sizes = new Set([64, 90, 126, 127].map((length) => pad(bytes(length)).length));

        expect(sizes).toEqual(new Set([128]));
    });

    it('round-trips', () => {
        for (const length of [0, 1, 63, 64, 65, 127, 4095, 4096, 9000]) {
            const plaintext = crypto.getRandomValues(new Uint8Array(length));

            expect(unpad(pad(plaintext))).toEqual(plaintext);
        }
    });

    /** The two inputs a length-agnostic delimiter scheme has to get right. */
    it('round-trips plaintext that ends in the padding bytes', () => {
        for (const trailing of [0x00, 0x80]) {
            const plaintext = new Uint8Array([0x7b, 0x7d, trailing]);

            expect(unpad(pad(plaintext))).toEqual(plaintext);
        }
    });

    it('round-trips a plaintext of all zeroes', () => {
        expect(unpad(pad(bytes(40, 0x00)))).toEqual(bytes(40, 0x00));
    });

    it('pushes a plaintext that exactly fills a bucket into the next one', () => {
        // The delimiter is always written, so there is never a bucket with no
        // room left for it — which is what keeps unpad free of special cases.
        expect(pad(bytes(MIN_BUCKET)).length).toBe(2 * MIN_BUCKET);
    });

    it('does not copy the plaintext into the tail', () => {
        const padded = pad(bytes(4, 0xff));

        expect([...padded.slice(4)]).toEqual([0x80, ...new Array<number>(MIN_BUCKET - 5).fill(0)]);
    });
});

describe('refusing malformed padding', () => {
    it('rejects a payload with no delimiter', () => {
        expect(() => unpad(bytes(MIN_BUCKET, 0x41))).toThrow(MalformedEnvelopeError);
    });

    it('rejects an all-zero buffer', () => {
        expect(() => unpad(bytes(MIN_BUCKET, 0x00))).toThrow(MalformedEnvelopeError);
    });

    it('rejects an empty buffer', () => {
        expect(() => unpad(new Uint8Array(0))).toThrow(MalformedEnvelopeError);
    });

    /**
     * An unpadded v1 payload run through unpad by mistake. JSON ends in `}`,
     * so the failure is loud rather than a silently truncated secret.
     */
    it('rejects an unpadded JSON payload', () => {
        const json = new TextEncoder().encode('{"key":"aws","value":"hunter2"}');

        expect(() => unpad(json)).toThrow(/no padding delimiter/);
    });
});
