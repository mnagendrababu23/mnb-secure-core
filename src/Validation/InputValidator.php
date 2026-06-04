<?php
namespace Mnb\SecurityCore\Validation;

use Mnb\SecurityCore\Exceptions\ValidationException;

class InputValidator
{
    public function validate(array $data, array $rules): array
    {
        $errors = [];
        foreach ($rules as $field => $ruleString) {
            $rulesList = is_array($ruleString) ? $ruleString : explode('|', $ruleString);
            $value = $data[$field] ?? null;
            foreach ($rulesList as $rule) {
                [$name, $param] = array_pad(explode(':', (string)$rule, 2), 2, null);
                if ($name === 'required' && ($value === null || $value === '')) {
                    $errors[$field][] = 'required';
                }
                if ($name === 'email' && $value !== null && $value !== '' && !filter_var($value, FILTER_VALIDATE_EMAIL)) {
                    $errors[$field][] = 'email';
                }
                if ($name === 'integer' && $value !== null && filter_var($value, FILTER_VALIDATE_INT) === false) {
                    $errors[$field][] = 'integer';
                }
                if ($name === 'max' && $param !== null && is_string($value) && strlen($value) > (int)$param) {
                    $errors[$field][] = 'max:' . $param;
                }
                if ($name === 'min' && $param !== null && is_string($value) && strlen($value) < (int)$param) {
                    $errors[$field][] = 'min:' . $param;
                }
            }
        }
        if ($errors) {
            throw new ValidationException($errors);
        }
        return $data;
    }
}
