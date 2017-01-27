<?php

namespace Vault\Http\Requests\User;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Support\Facades\Auth;

class UpdateRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     *
     * @return bool
     */
    public function authorize()
    {
        return true;
    }

    /**
     * Get the validation rules that apply to the request.
     *
     * @return array
     */
    public function rules()
    {
        return [
            'uuid'      => 'required',
            'name'      => 'required',
            'email'     => 'required|email|unique:users,email,' . Auth::user()->id . ',id',
            'password'  => 'confirmed|min:6',
        ];
    }
}
