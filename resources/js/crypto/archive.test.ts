import { describe, expect, it } from 'vitest';

import {
    ARCHIVE_HEADER_LENGTH,
    ARCHIVE_KDF_PARAMS,
    ARCHIVE_MAGIC,
    ARCHIVE_SALT_LENGTH,
    ARCHIVE_VERSION,
    KDF_ARGON2ID,
    MIN_PASSPHRASE_LENGTH,
    openArchive,
    readArchiveHeader,
    sealArchive,
} from './archive';
import { IntegrityError, InvalidParameterError, MalformedEnvelopeError } from './errors';
import type { KdfParams } from './primitives';

/*
 | Argon2id at the real parameters costs seconds per call, which would put this
 | file at several minutes. The cost is a property of the header, not of the
 | code, so every test here runs at a cost nobody would ship and the one test
 | that cares about the real figure asserts the constant instead.
 */
const CHEAP: KdfParams = { m: 8, t: 1, p: 1 };

const UUID = '01a0024a-2847-7c4e-9f2b-3d5e6f708192';
const OTHER_UUID = '01a0024a-2850-7c4e-9f2b-3d5e6f708193';
const PASSPHRASE = 'correct-horse-battery-staple';

const plaintext = (text = '{"format":"vault.export"}') => new TextEncoder().encode(text);

const make = (text?: string, passphrase = PASSPHRASE, uuid = UUID) =>
    sealArchive(passphrase, plaintext(text), uuid, CHEAP);

describe('the header', () => {
    it('starts with the magic, so a file says what it is', () => {
        expect(make().slice(0, ARCHIVE_MAGIC.length)).toEqual(ARCHIVE_MAGIC);
        expect(new TextDecoder().decode(ARCHIVE_MAGIC)).toBe('VAULTARC');
    });

    it('carries everything needed to derive the key', () => {
        const header = readArchiveHeader(make());

        expect(header).toEqual({
            version: ARCHIVE_VERSION,
            kdf: KDF_ARGON2ID,
            params: CHEAP,
            salt: expect.any(Uint8Array) as Uint8Array,
            uuid: UUID,
        });
        expect(header.salt.length).toBe(ARCHIVE_SALT_LENGTH);
    });

    it('reads without a passphrase, so the wrong file is caught before the cost is paid', () => {
        expect(readArchiveHeader(make()).uuid).toBe(UUID);
    });

    it('uses a fresh salt for every archive', () => {
        expect(readArchiveHeader(make()).salt).not.toEqual(readArchiveHeader(make()).salt);
    });

    it('refuses anything too short to be an archive', () => {
        expect(() => readArchiveHeader(new Uint8Array(ARCHIVE_HEADER_LENGTH - 1))).toThrow(
            MalformedEnvelopeError,
        );
    });

    it('refuses a file that does not begin with the magic', () => {
        const archive = make();
        archive[3] = 0x00;

        expect(() => readArchiveHeader(archive)).toThrow(/not an archive/);
    });

    it('refuses a version it does not know', () => {
        const archive = make();
        archive[ARCHIVE_MAGIC.length] = 99;

        expect(() => readArchiveHeader(archive)).toThrow(/version 99/);
    });

    it('refuses a key derivation it does not know', () => {
        const archive = make();
        archive[ARCHIVE_MAGIC.length + 1] = 7;

        expect(() => readArchiveHeader(archive)).toThrow(/not Argon2id/);
    });
});

describe('sealing and opening', () => {
    it('round-trips', () => {
        expect(new TextDecoder().decode(openArchive(PASSPHRASE, make('hello')))).toBe('hello');
    });

    it('round-trips an empty document', () => {
        expect(openArchive(PASSPHRASE, make('')).length).toBe(0);
    });

    it('refuses the wrong passphrase', () => {
        expect(() => openArchive('wrong-passphrase-entirely', make())).toThrow(IntegrityError);
    });

    it('refuses a passphrase shorter than the floor', () => {
        expect(() => sealArchive('a'.repeat(MIN_PASSPHRASE_LENGTH - 1), plaintext(), UUID, CHEAP)).toThrow(
            InvalidParameterError,
        );
    });

    it('accepts one exactly at the floor', () => {
        expect(() => sealArchive('a'.repeat(MIN_PASSPHRASE_LENGTH), plaintext(), UUID, CHEAP)).not.toThrow();
    });

    it('produces a different ciphertext each time, from the salt and the nonce', () => {
        expect(make('same')).not.toEqual(make('same'));
    });
});

/*
 | The point of binding the header through the key derivation rather than
 | leaving it as unauthenticated framing. Every one of these edits is something
 | an attacker with the file could try, and every one of them has to fail.
 */
describe('the header is bound to the body', () => {
    const tamper = (offset: number): Uint8Array => {
        const archive = make();
        archive[offset] = archive[offset]! ^ 0xff;

        return archive;
    };

    it('rejects an edited cost parameter', () => {
        // The low byte of the memory cost: still a plausible number afterwards,
        // so it reaches the derivation and fails there rather than at the header
        // check. That is the case this binding exists for.
        expect(() => openArchive(PASSPHRASE, tamper(ARCHIVE_MAGIC.length + 5))).toThrow(IntegrityError);
    });

    it('refuses an implausible cost rather than trying to allocate it', () => {
        // The top byte, which turns 8 KiB into four terabytes. Caught while
        // reading the header, because the alternative is a runtime allocation
        // failure several seconds after somebody typed their passphrase.
        expect(() => openArchive(PASSPHRASE, tamper(ARCHIVE_MAGIC.length + 2))).toThrow(
            /not a plausible header/,
        );
    });

    it('refuses an implausible pass count or parallelism', () => {
        expect(() => openArchive(PASSPHRASE, tamper(ARCHIVE_MAGIC.length + 6))).toThrow(
            /not a plausible header/,
        );
        expect(() => openArchive(PASSPHRASE, tamper(ARCHIVE_MAGIC.length + 10))).toThrow(
            /not a plausible header/,
        );
    });

    it('rejects an edited salt', () => {
        expect(() => openArchive(PASSPHRASE, tamper(ARCHIVE_MAGIC.length + 14))).toThrow(IntegrityError);
    });

    it('rejects an archive whose UUID was changed', () => {
        const archive = make();
        archive.set(new TextEncoder().encode(OTHER_UUID), ARCHIVE_HEADER_LENGTH - OTHER_UUID.length);

        expect(() => openArchive(PASSPHRASE, archive)).toThrow(IntegrityError);
    });

    it('rejects a body moved into another archive of its own', () => {
        // Same length, so the swap is a substitution rather than a truncation
        // — otherwise the test would pass for the wrong reason.
        const donor = make('the other one');
        const host = make('this one!!!!!');

        host.set(donor.slice(ARCHIVE_HEADER_LENGTH), ARCHIVE_HEADER_LENGTH);

        expect(() => openArchive(PASSPHRASE, host)).toThrow(IntegrityError);
    });

    it('rejects a truncated archive', () => {
        const archive = make('a longer document to have something to remove');

        expect(() => openArchive(PASSPHRASE, archive.slice(0, archive.length - 1))).toThrow(IntegrityError);
    });

    it('rejects a flipped bit in the body', () => {
        const archive = make();
        const last = archive.length - 1;
        archive[last] = archive[last]! ^ 0x01;

        expect(() => openArchive(PASSPHRASE, archive)).toThrow(IntegrityError);
    });
});

describe('the shipped parameters', () => {
    /*
     | Asserted rather than exercised. Somebody lowering these to make a test
     | faster, or copying the login defaults over them, is the realistic way this
     | gets weakened — and it would not fail any other test in this file.
     */
    it('are harder than a login, because an archive is opened once', () => {
        expect(ARCHIVE_KDF_PARAMS.m).toBeGreaterThanOrEqual(256 * 1024);
        expect(ARCHIVE_KDF_PARAMS.t).toBeGreaterThanOrEqual(4);
    });

    it('are written into the archive rather than assumed by the reader', () => {
        expect(readArchiveHeader(make()).params).toEqual(CHEAP);
        expect(readArchiveHeader(sealArchive(PASSPHRASE, plaintext(), UUID, CHEAP)).params).not.toEqual(
            ARCHIVE_KDF_PARAMS,
        );
    });
});
