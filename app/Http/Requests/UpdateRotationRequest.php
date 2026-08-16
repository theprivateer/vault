<?php

namespace App\Http\Requests;

use Closure;
use Illuminate\Foundation\Http\FormRequest;

/**
 * How often a vault would like to be reminded to rotate its key.
 *
 * A reminder, not a schedule. The server cannot rotate a Vault Key on a timer —
 * unwrapping the current one needs a member's browser — so the only thing this
 * number can ever do is decide when the interface starts saying the key is old.
 *
 * Null defers to the deployment default, as elsewhere. Zero means never, and is
 * a considered answer rather than a disabled feature: periodic rotation of a
 * vault key does not re-protect anything already written, since payload
 * ciphertexts are untouched by a rotation. It bounds how long a leaked Vault Key
 * keeps opening things written *after* the leak, which is worth having when you
 * think a key escaped and close to worthless as a calendar ritual.
 */
class UpdateRotationRequest extends FormRequest
{
    /** The shortest reminder interval worth offering. */
    public const MIN_DAYS = 7;

    public function authorize(): bool
    {
        // The route's `can:rekey,vault` decides this. See .ai/rules/routes.md.
        return true;
    }

    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return [
            /*
             | Zero, or at least a week. A daily reminder to perform an operation
             | that needs an owner at a keyboard is one people learn to dismiss,
             | and a control whose entire effect is a badge is worth nothing once
             | the badge is background noise.
             */
            'after_days' => [
                'present',
                'nullable',
                'integer',
                'min:0',
                'max:3650',
                function (string $attribute, mixed $value, Closure $fail): void {
                    if (is_numeric($value) && (int) $value > 0 && (int) $value < self::MIN_DAYS) {
                        $fail('Remind me no more often than weekly, or use 0 for never.');
                    }
                },
            ],
        ];
    }

    /**
     * @return array<string, string>
     */
    public function messages(): array
    {
        return [
            'after_days.max' => 'A reminder ten years out is the same as no reminder. Use 0 for never.',
        ];
    }
}
