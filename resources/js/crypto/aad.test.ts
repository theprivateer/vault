import { describe, expect, it } from 'vitest';

import type { AadContext } from './aad';
import { AAD_CONTEXTS, buildAad, buildChunkAad } from './aad';
import { InvalidParameterError } from './errors';

const SUBJECT = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f6';
const OTHER_SUBJECT = '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f7';

/** Built rather than escaped: a literal NUL in source is invisible to a reader. */
const NUL = String.fromCharCode(0);

const decode = (bytes: Uint8Array) => new TextDecoder().decode(bytes);

describe('structure', () => {
    it('builds the documented layout', () => {
        const aad = buildAad({ context: 'secret.payload', subject: SUBJECT, version: 1 });

        expect(decode(aad)).toBe(['vault.v1', 'secret.payload', SUBJECT, '1'].join(NUL));
    });

    it('is deterministic', () => {
        const params = { context: 'vault.payload', subject: SUBJECT, version: 3 } as const;

        expect(buildAad(params)).toEqual(buildAad(params));
    });

    it('normalises the subject to lower case', () => {
        expect(buildAad({ context: 'vault.payload', subject: SUBJECT.toUpperCase(), version: 1 })).toEqual(
            buildAad({ context: 'vault.payload', subject: SUBJECT, version: 1 }),
        );
    });
});

describe('distinctness', () => {
    it('differs for every context', () => {
        const encoded = AAD_CONTEXTS.map((context) =>
            decode(buildAad({ context, subject: SUBJECT, version: 1 })),
        );

        expect(new Set(encoded).size).toBe(AAD_CONTEXTS.length);
    });

    it('differs by subject', () => {
        expect(buildAad({ context: 'secret.payload', subject: SUBJECT, version: 1 })).not.toEqual(
            buildAad({ context: 'secret.payload', subject: OTHER_SUBJECT, version: 1 }),
        );
    });

    it('differs by version', () => {
        expect(buildAad({ context: 'secret.payload', subject: SUBJECT, version: 1 })).not.toEqual(
            buildAad({ context: 'secret.payload', subject: SUBJECT, version: 2 }),
        );
    });

    /*
     | The NUL separators are only unambiguous because no field can contain a
     | NUL. If a crafted subject could produce the same bytes as a different
     | record's AAD, the binding would be defeated without breaking any tag.
     */
    it('cannot be made ambiguous by a crafted subject', () => {
        expect(() =>
            buildAad({ context: 'secret.payload', subject: `${SUBJECT}${NUL}999`, version: 1 }),
        ).toThrow(InvalidParameterError);
    });
});

describe('validation', () => {
    it.each([
        ['not-a-uuid', 'free text'],
        ['', 'empty'],
        ['0192f3a14b2c7d3e8f90a1b2c3d4e5f6', 'no dashes'],
        ['0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f', 'too short'],
        ['0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f67', 'too long'],
        ['0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5fg', 'non-hex character'],
        ['../../../etc/passwd', 'a traversal attempt'],
    ])('rejects the subject %s (%s)', (subject) => {
        expect(() => buildAad({ context: 'secret.payload', subject, version: 1 })).toThrow(
            InvalidParameterError,
        );
    });

    it.each([-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, Number.MAX_SAFE_INTEGER + 1])(
        'rejects the version %p',
        (version) => {
            expect(() => buildAad({ context: 'secret.payload', subject: SUBJECT, version })).toThrow(
                InvalidParameterError,
            );
        },
    );

    it('rejects a context outside the closed set', () => {
        expect(() =>
            buildAad({ context: 'secret.paylaod' as AadContext, subject: SUBJECT, version: 1 }),
        ).toThrow(InvalidParameterError);
    });

    it('accepts version zero', () => {
        expect(() => buildAad({ context: 'secret.payload', subject: SUBJECT, version: 0 })).not.toThrow();
    });
});

/**
 * The chunk AAD, which is where truncation and reordering are actually stopped.
 *
 * Both extra fields matter and they stop different things: the index stops a
 * chunk being served from another position, and the count stops the file being
 * cut short. Neither is checked anywhere in the application — the tag is what
 * enforces them — so what is asserted here is that both really are in the bytes
 * the cipher will authenticate.
 */
describe('file chunks', () => {
    it('extends the base layout with the index and the count', () => {
        const aad = buildChunkAad({
            context: 'file.chunk',
            subject: SUBJECT,
            version: 2,
            chunkIndex: 3,
            chunkCount: 40,
        });

        expect(decode(aad)).toBe(['vault.v1', 'file.chunk', SUBJECT, '2', '3', '40'].join(NUL));
    });

    it('differs for every position, count and file', () => {
        const base = { context: 'file.chunk' as const, subject: SUBJECT, version: 2 };

        const variants = [
            buildChunkAad({ ...base, chunkIndex: 0, chunkCount: 40 }),
            buildChunkAad({ ...base, chunkIndex: 1, chunkCount: 40 }),
            buildChunkAad({ ...base, chunkIndex: 0, chunkCount: 39 }),
            buildChunkAad({ ...base, subject: OTHER_SUBJECT, chunkIndex: 0, chunkCount: 40 }),
        ].map(decode);

        expect(new Set(variants).size).toBe(variants.length);
    });

    it.each([
        [-1, 4, 'a negative index'],
        [4, 4, 'an index at the count'],
        [5, 4, 'an index past the count'],
        [1.5, 4, 'a fractional index'],
        [0, 0, 'a file of no chunks'],
        [0, -1, 'a negative count'],
        [0, 1.5, 'a fractional count'],
    ])('rejects index %p of %p (%s)', (chunkIndex, chunkCount) => {
        expect(() =>
            buildChunkAad({
                context: 'file.chunk',
                subject: SUBJECT,
                version: 2,
                chunkIndex,
                chunkCount,
            }),
        ).toThrow(InvalidParameterError);
    });

    it('still validates the subject and version it inherits', () => {
        expect(() =>
            buildChunkAad({
                context: 'file.chunk',
                subject: 'not-a-uuid',
                version: 2,
                chunkIndex: 0,
                chunkCount: 1,
            }),
        ).toThrow(InvalidParameterError);
    });
});
