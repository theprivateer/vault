/**
 * The rule: never replace what happened with a guess about what happened.
 *
 * These are small tests for a small function, and they exist because the bug
 * they prevent has cost this project two debugging sessions. Both times the
 * interface said "something went wrong" about an environment problem that had
 * nothing to do with the operation it named.
 */
import { describe, expect, it } from 'vitest';

import { IntegrityError, WorkerUnavailableError } from '@/crypto/errors';

import { describeError } from './errors';

describe('describeError', () => {
    it('lets a crypto error speak for itself', () => {
        const error = new WorkerUnavailableError(
            'The worker could not be started. Run npm run build:worker.',
        );

        expect(describeError(error, 'Your keys could not be generated.')).toBe(error.message);
    });

    it('keeps an integrity failure naming its record', () => {
        const message = describeError(
            new IntegrityError('secret.payload', '0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f6'),
            'Your keys could not be generated.',
        );

        expect(message).toContain('secret.payload');
        expect(message).toContain('0192f3a1-4b2c-7d3e-8f90-a1b2c3d4e5f6');
    });

    /*
     | The case that matters most. A CSP-blocked Worker arrives as a
     | SecurityError and a failed fetch as a TypeError — the *type* is most of
     | the diagnosis, and swallowing it is what made this invisible before.
     */
    it('reports an unexpected error with its type and message', () => {
        const security = new Error('Refused to create a worker');
        security.name = 'SecurityError';

        expect(describeError(security, 'Your keys could not be generated.')).toBe(
            'Your keys could not be generated. (SecurityError: Refused to create a worker)',
        );
    });

    it('falls back cleanly when there is nothing to add', () => {
        expect(describeError(new Error(''), 'Your keys could not be generated.')).toBe(
            'Your keys could not be generated.',
        );

        expect(describeError('not an error', 'Your keys could not be generated.')).toBe(
            'Your keys could not be generated.',
        );
    });
});
