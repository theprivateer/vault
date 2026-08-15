import { describe, expect, it } from 'vitest';

import { isTypingTarget, matches, triggers } from './shortcuts';

const stroke = (key: string, modifiers: Record<string, boolean> = {}) => ({ key, ...modifiers });

describe('matching', () => {
    it('matches a plain key', () => {
        expect(matches(stroke('Escape'), 'escape')).toBe(true);
    });

    it('is case insensitive on both sides', () => {
        expect(matches(stroke('K', { metaKey: true }), 'mod+k')).toBe(true);
        expect(matches(stroke('k', { metaKey: true }), 'MOD+K')).toBe(true);
    });

    it('accepts either Command or Control for mod', () => {
        expect(matches(stroke('k', { metaKey: true }), 'mod+k')).toBe(true);
        expect(matches(stroke('k', { ctrlKey: true }), 'mod+k')).toBe(true);
    });

    it('does not fire a modified binding without its modifier', () => {
        expect(matches(stroke('k'), 'mod+k')).toBe(false);
    });

    /** Otherwise ⌘K would fire the bare `k` binding as well as its own. */
    it('does not fire a bare binding when a modifier is held', () => {
        expect(matches(stroke('k', { metaKey: true }), 'k')).toBe(false);
    });

    it('distinguishes shift', () => {
        expect(matches(stroke('?', { shiftKey: true }), 'shift+?')).toBe(true);
        expect(matches(stroke('?'), 'shift+?')).toBe(false);
    });

    it('distinguishes alt', () => {
        expect(matches(stroke('n', { altKey: true }), 'alt+n')).toBe(true);
        expect(matches(stroke('n'), 'alt+n')).toBe(false);
    });

    it('does not match a different key', () => {
        expect(matches(stroke('j', { metaKey: true }), 'mod+k')).toBe(false);
    });
});

describe('typing targets', () => {
    it('recognises the elements that own the keyboard', () => {
        expect(isTypingTarget({ tagName: 'INPUT' })).toBe(true);
        expect(isTypingTarget({ tagName: 'TEXTAREA' })).toBe(true);
        expect(isTypingTarget({ tagName: 'SELECT' })).toBe(true);
        expect(isTypingTarget({ isContentEditable: true })).toBe(true);
    });

    it('does not treat anything else as one', () => {
        expect(isTypingTarget({ tagName: 'DIV' })).toBe(false);
        expect(isTypingTarget(null)).toBe(false);
        expect(isTypingTarget(undefined)).toBe(false);
        expect(isTypingTarget('input')).toBe(false);
    });
});

describe('triggering', () => {
    /**
     * The failure this prevents: typing a password containing `/` into a
     * masked field, having the search palette open, and the rest of the
     * password going into it — where the user cannot see what happened.
     */
    it('does not fire a bare shortcut while the user is typing', () => {
        expect(triggers(stroke('/'), '/', { tagName: 'INPUT' })).toBe(false);
    });

    it('fires a bare shortcut outside a field', () => {
        expect(triggers(stroke('/'), '/', { tagName: 'DIV' })).toBe(true);
    });

    it('still fires a modified shortcut inside a field', () => {
        expect(triggers(stroke('k', { metaKey: true }), 'mod+k', { tagName: 'INPUT' })).toBe(true);
    });

    it('fires a bare shortcut when there is no target at all', () => {
        expect(triggers(stroke('escape'), 'escape')).toBe(true);
    });
});
