/**
 * Keyboard shortcut matching, kept out of the components so it can be tested
 * without a DOM.
 *
 * A vault is a tool people use dozens of times a day, and reaching for a mouse
 * to copy a password is the difference between a manager that gets used and one
 * that gets worked around — which in practice means passwords written down
 * somewhere worse. Keyboard-first is a security property here, not a
 * preference.
 */

/** Written the way a user would say it: `mod+k`, `shift+/`, `escape`. */
export type Binding = string;

/** The subset of a KeyboardEvent that matching depends on. */
export interface KeyStroke {
    key: string;
    metaKey?: boolean;
    ctrlKey?: boolean;
    shiftKey?: boolean;
    altKey?: boolean;
}

/**
 * `mod` is Command on Apple platforms and Control everywhere else.
 *
 * Matched as "either one" rather than sniffed from the platform: a user on a
 * Mac with an external PC keyboard uses Control, and a browser reporting an
 * unhelpful userAgent should not cost them the shortcut. Accepting both costs
 * nothing — no shortcut here means one thing under Command and another under
 * Control.
 */
function modifierHeld(stroke: KeyStroke): boolean {
    return stroke.metaKey === true || stroke.ctrlKey === true;
}

export function matches(stroke: KeyStroke, binding: Binding): boolean {
    const parts = binding.toLowerCase().split('+');
    const key = parts[parts.length - 1] ?? '';

    if (stroke.key.toLowerCase() !== key) {
        return false;
    }

    const wantsMod = parts.includes('mod');
    const wantsShift = parts.includes('shift');
    const wantsAlt = parts.includes('alt');

    return (
        wantsMod === modifierHeld(stroke) &&
        wantsShift === (stroke.shiftKey === true) &&
        wantsAlt === (stroke.altKey === true)
    );
}

/** Elements that own the keyboard while they have focus. */
const TYPING_TAGS = new Set(['INPUT', 'TEXTAREA', 'SELECT']);

/**
 * True when the user is typing into something, so a bare-letter shortcut must
 * not fire.
 *
 * Without this, typing a password containing `/` opens the search palette and
 * the rest of the password goes into it — which, for a value the user cannot
 * see because it is masked, is a genuinely nasty way to lose data. Shortcuts
 * carrying a modifier are still allowed through, since `mod+k` is not something
 * anyone types by accident.
 */
export function isTypingTarget(target: unknown): boolean {
    if (target === null || typeof target !== 'object') {
        return false;
    }

    const element = target as { tagName?: unknown; isContentEditable?: unknown };

    return (
        (typeof element.tagName === 'string' && TYPING_TAGS.has(element.tagName)) ||
        element.isContentEditable === true
    );
}

/**
 * Should this stroke trigger `binding`, given where it landed?
 *
 * One function rather than two checks at each call site, because the call sites
 * that forget the second check are the ones that eat a keystroke out of a
 * password field.
 */
export function triggers(stroke: KeyStroke, binding: Binding, target?: unknown): boolean {
    if (!matches(stroke, binding)) {
        return false;
    }

    const bare = !binding.toLowerCase().includes('mod+');

    return !(bare && isTypingTarget(target));
}
