<?php
namespace Mnb\SecurityCore\Validation;

use Mnb\SecurityCore\Exceptions\ValidationException;

class InputValidator
{
    /** @param array<string,mixed> $data @param array<string,string|array<int,string>> $rules */
    public function validate(array $data, array $rules): array
    {
        $errors = [];
        foreach ($rules as $field => $ruleString) {
            $rulesList = $this->normalizeRules($ruleString);
            $present = array_key_exists($field, $data);
            $value = $data[$field] ?? null;
            $nullable = in_array('nullable', array_map(fn(string $rule): string => strtolower(strtok($rule, ':') ?: $rule), $rulesList), true);
            $sometimes = in_array('sometimes', array_map(fn(string $rule): string => strtolower(strtok($rule, ':') ?: $rule), $rulesList), true);

            if ($sometimes && !$present) {
                continue;
            }
            if ($nullable && ($value === null || $value === '')) {
                continue;
            }

            foreach ($rulesList as $rule) {
                [$name, $param] = array_pad(explode(':', (string)$rule, 2), 2, null);
                $name = strtolower(trim($name));
                if (in_array($name, ['nullable', 'sometimes', 'bail'], true)) {
                    continue;
                }

                $failed = $this->fails($name, $value, $param, $data, $present, (string)$field);
                if ($failed !== null) {
                    $errors[$field][] = $failed;
                    if (in_array('bail', $rulesList, true)) {
                        break;
                    }
                }
            }
        }
        if ($errors) {
            throw new ValidationException($errors);
        }
        return $data;
    }

    /** @param array<string,mixed> $data @param array<string,string|array<int,string>> $rules */
    public function passes(array $data, array $rules): bool
    {
        try {
            $this->validate($data, $rules);
            return true;
        } catch (ValidationException) {
            return false;
        }
    }

    /** @param string|array<int,string> $ruleString @return array<int,string> */
    private function normalizeRules(string|array $ruleString): array
    {
        if (is_array($ruleString)) {
            return array_values(array_filter(array_map('strval', $ruleString), fn(string $rule): bool => trim($rule) !== ''));
        }
        return array_values(array_filter(array_map('trim', explode('|', $ruleString)), fn(string $rule): bool => $rule !== ''));
    }

    /** @param array<string,mixed> $data */
    private function fails(string $name, mixed $value, ?string $param, array $data, bool $present, string $field): ?string
    {
        return match ($name) {
            'required' => ($value === null || $value === '') ? 'required' : null,
            'required_if' => $this->requiredIfFails($value, $param, $data),
            'required_without' => $this->requiredWithoutFails($value, $param, $data),
            'filled' => ($present && ($value === null || $value === '')) ? 'filled' : null,
            'email' => ($value !== null && $value !== '' && !filter_var($value, FILTER_VALIDATE_EMAIL)) ? 'email' : null,
            'integer', 'int' => ($value !== null && $value !== '' && filter_var($value, FILTER_VALIDATE_INT) === false) ? 'integer' : null,
            'numeric', 'number' => ($value !== null && $value !== '' && !is_numeric($value)) ? 'numeric' : null,
            'boolean', 'bool' => ($value !== null && $value !== '' && filter_var($value, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE) === null) ? 'boolean' : null,
            'string' => ($value !== null && !is_string($value)) ? 'string' : null,
            'array' => ($value !== null && !is_array($value)) ? 'array' : null,
            'min' => $this->minFails($value, $param),
            'max' => $this->maxFails($value, $param),
            'between' => $this->betweenFails($value, $param),
            'size' => $this->sizeFails($value, $param),
            'in' => $this->inFails($value, $param),
            'not_in' => $this->notInFails($value, $param),
            'regex' => $this->regexFails($value, $param),
            'alpha' => ($value !== null && $value !== '' && !preg_match('/^[\pL]+$/u', (string)$value)) ? 'alpha' : null,
            'alpha_num' => ($value !== null && $value !== '' && !preg_match('/^[\pL\pN]+$/u', (string)$value)) ? 'alpha_num' : null,
            'slug' => ($value !== null && $value !== '' && !preg_match('/^[a-z0-9]+(?:-[a-z0-9]+)*$/', (string)$value)) ? 'slug' : null,
            'url' => ($value !== null && $value !== '' && !filter_var($value, FILTER_VALIDATE_URL)) ? 'url' : null,
            'ip' => ($value !== null && $value !== '' && !filter_var($value, FILTER_VALIDATE_IP)) ? 'ip' : null,
            'uuid' => ($value !== null && $value !== '' && !preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i', (string)$value)) ? 'uuid' : null,
            'date' => $this->dateFails($value),
            'json' => $this->jsonFails($value),
            'confirmed' => (($data[$param ?: ($field . '_confirmation')] ?? null) !== $value) ? 'confirmed' : null,
            'same' => (($data[$param ?? ''] ?? null) !== $value) ? 'same:' . $param : null,
            'different' => (($data[$param ?? ''] ?? null) === $value) ? 'different:' . $param : null,
            default => null,
        };
    }

    /** @param array<string,mixed> $data */
    private function requiredIfFails(mixed $value, ?string $param, array $data): ?string
    {
        [$field, $expected] = array_pad(explode(',', (string)$param, 2), 2, null);
        if ($field !== null && array_key_exists($field, $data) && (string)$data[$field] === (string)$expected && ($value === null || $value === '')) {
            return 'required_if:' . $param;
        }
        return null;
    }

    /** @param array<string,mixed> $data */
    private function requiredWithoutFails(mixed $value, ?string $param, array $data): ?string
    {
        $field = (string)$param;
        if (in_array($data[$field] ?? null, [null, ''], true)) {
            return ($value === null || $value === '') ? 'required_without:' . $field : null;
        }
        return null;
    }

    private function minFails(mixed $value, ?string $param): ?string
    {
        if ($value === null || $param === null) return null;
        $min = (float)$param;
        if (is_numeric($value)) return (float)$value < $min ? 'min:' . $param : null;
        if (is_string($value)) return strlen($value) < (int)$param ? 'min:' . $param : null;
        if (is_array($value)) return count($value) < (int)$param ? 'min:' . $param : null;
        return null;
    }

    private function maxFails(mixed $value, ?string $param): ?string
    {
        if ($value === null || $param === null) return null;
        $max = (float)$param;
        if (is_numeric($value)) return (float)$value > $max ? 'max:' . $param : null;
        if (is_string($value)) return strlen($value) > (int)$param ? 'max:' . $param : null;
        if (is_array($value)) return count($value) > (int)$param ? 'max:' . $param : null;
        return null;
    }

    private function betweenFails(mixed $value, ?string $param): ?string
    {
        [$min, $max] = array_pad(explode(',', (string)$param, 2), 2, null);
        if ($min === null || $max === null) return null;
        return ($this->minFails($value, $min) !== null || $this->maxFails($value, $max) !== null) ? 'between:' . $param : null;
    }

    private function sizeFails(mixed $value, ?string $param): ?string
    {
        if ($value === null || $param === null) return null;
        if (is_string($value)) return strlen($value) !== (int)$param ? 'size:' . $param : null;
        if (is_array($value)) return count($value) !== (int)$param ? 'size:' . $param : null;
        if (is_numeric($value)) return (float)$value !== (float)$param ? 'size:' . $param : null;
        return null;
    }

    private function inFails(mixed $value, ?string $param): ?string
    {
        if ($value === null || $value === '' || $param === null) return null;
        $allowed = array_map('trim', explode(',', $param));
        return in_array((string)$value, $allowed, true) ? null : 'in:' . $param;
    }

    private function notInFails(mixed $value, ?string $param): ?string
    {
        if ($value === null || $value === '' || $param === null) return null;
        $blocked = array_map('trim', explode(',', $param));
        return in_array((string)$value, $blocked, true) ? 'not_in:' . $param : null;
    }

    private function regexFails(mixed $value, ?string $param): ?string
    {
        if ($value === null || $value === '' || $param === null) return null;
        set_error_handler(static fn(): bool => true);
        try {
            $ok = preg_match($param, (string)$value) === 1;
        } finally {
            restore_error_handler();
        }
        return $ok ? null : 'regex';
    }

    private function dateFails(mixed $value): ?string
    {
        if ($value === null || $value === '') return null;
        return strtotime((string)$value) === false ? 'date' : null;
    }

    private function jsonFails(mixed $value): ?string
    {
        if ($value === null || $value === '') return null;
        if (!is_string($value)) return 'json';
        json_decode($value, true);
        return json_last_error() === JSON_ERROR_NONE ? null : 'json';
    }

}
