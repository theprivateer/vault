<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

/**
 * How much history a vault keeps.
 *
 * Both fields are nullable, and null is a real answer rather than an omission:
 * it means "whatever the deployment's default is", so a vault that has never
 * expressed an opinion follows the default as it changes instead of being
 * frozen at whatever it happened to be on the day somebody opened this form.
 */
class UpdateRetentionRequest extends FormRequest
{
    public function authorize(): bool
    {
        // The route's `can:configure,vault` decides this. A policy against a
        // resolved record cannot be evaluated from request input.
        return true;
    }

    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return [
            /*
             | Zero is allowed, and it is the point of having the setting at
             | all: a vault holding credentials that get rotated *because* they
             | leak wants no archive of the leaked value anywhere. The ceiling
             | is a sanity bound, not a considered maximum — nobody needs five
             | hundred versions of one password, and the column is a smallint.
             */
            'max_versions' => ['present', 'nullable', 'integer', 'min:0', 'max:500'],

            /*
             | At least a day, because "zero days" and "no history" are the same
             | request expressed twice, and one setting that can mean the other
             | is a setting somebody will get wrong. Turning history off is
             | `max_versions = 0`, and only that.
             */
            'max_age_days' => ['present', 'nullable', 'integer', 'min:1', 'max:3650'],
        ];
    }
}
