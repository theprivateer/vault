import { describe, expect, it } from 'vitest';

import { uuid7 } from './uuid';

const UUID7_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

describe('uuid7', () => {
    it('matches the shape the server validates', () => {
        // The registration request validates `uuid:7`, so a v4 here would be
        // rejected server-side.
        expect(uuid7()).toMatch(UUID7_PATTERN);
    });

    it('sets the version and variant bits', () => {
        for (let i = 0; i < 100; i++) {
            expect(uuid7()).toMatch(UUID7_PATTERN);
        }
    });

    it('encodes the timestamp big-endian in the first 48 bits', () => {
        const now = 0x018f_1234_5678;

        expect(uuid7(now).replace(/-/g, '').slice(0, 12)).toBe('018f12345678');
    });

    it('sorts lexicographically by creation time', () => {
        const early = uuid7(1_700_000_000_000);
        const late = uuid7(1_800_000_000_000);

        expect(early < late).toBe(true);
    });

    it('does not repeat', () => {
        const ids = new Set(Array.from({ length: 500 }, () => uuid7()));

        expect(ids.size).toBe(500);
    });
});
