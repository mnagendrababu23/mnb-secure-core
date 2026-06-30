<?php
namespace Mnb\SecurityCore\Validation;

class InputSanitizer
{
    /** @param array<string,mixed> $data @param array<string,string|array<int,string>> $rules */
    public function sanitize(array $data, array $rules = [], array $options = []): array
    {
        $allowedFields = $options['allowed_fields'] ?? null;
        if (is_array($allowedFields)) {
            $data = array_intersect_key($data, array_flip(array_map('strval', $allowedFields)));
        }

        $blockedKeys = array_map('strtolower', array_map('strval', $options['blocked_keys'] ?? ['__proto__', 'prototype', 'constructor']));
        $maxDepth = max(1, (int)($options['max_depth'] ?? 10));
        $maxStringLength = max(1, (int)($options['max_string_length'] ?? 10000));

        return $this->sanitizeArray($data, $rules, $blockedKeys, $maxDepth, $maxStringLength, 0);
    }

    /** @param array<string,mixed> $data @param array<string,string|array<int,string>> $rules @param array<int,string> $blockedKeys */
    private function sanitizeArray(array $data, array $rules, array $blockedKeys, int $maxDepth, int $maxStringLength, int $depth): array
    {
        if ($depth > $maxDepth) {
            return [];
        }

        $clean = [];
        foreach ($data as $key => $value) {
            $key = is_int($key) ? $key : $this->sanitizeKey((string)$key);
            if (is_string($key) && in_array(strtolower($key), $blockedKeys, true)) {
                continue;
            }

            $fieldRules = $this->rulesFor((string)$key, $rules);
            if (is_array($value)) {
                $clean[$key] = $this->sanitizeArray($value, $rules, $blockedKeys, $maxDepth, $maxStringLength, $depth + 1);
                continue;
            }

            $clean[$key] = $this->sanitizeValue($value, $fieldRules, $maxStringLength);
        }

        return $clean;
    }

    /** @param array<string,string|array<int,string>> $rules @return array<int,string> */
    private function rulesFor(string $field, array $rules): array
    {
        $ruleString = $rules[$field] ?? $rules['*'] ?? ['trim', 'strip_control_chars'];
        if (is_string($ruleString)) {
            return array_values(array_filter(array_map('trim', explode('|', $ruleString)), fn(string $rule): bool => $rule !== ''));
        }
        if (is_array($ruleString)) {
            return array_values(array_filter(array_map('strval', $ruleString), fn(string $rule): bool => trim($rule) !== ''));
        }
        return ['trim', 'strip_control_chars'];
    }

    /** @param array<int,string> $rules */
    public function sanitizeValue(mixed $value, array $rules = [], int $maxStringLength = 10000): mixed
    {
        if ($value === null || is_bool($value) || is_int($value) || is_float($value)) {
            return $value;
        }

        if (!is_scalar($value)) {
            return $value;
        }

        $value = (string)$value;
        foreach ($rules ?: ['trim', 'strip_control_chars'] as $rule) {
            [$name, $param] = array_pad(explode(':', trim((string)$rule), 2), 2, null);
            $name = strtolower($name);

            $value = match ($name) {
                'trim' => trim($value),
                'ltrim' => ltrim($value),
                'rtrim' => rtrim($value),
                'strip_tags', 'tags' => strip_tags($value),
                'strip_control_chars', 'control' => preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u', '', $value) ?? '',
                'collapse_spaces', 'spaces' => preg_replace('/\s+/u', ' ', $value) ?? '',
                'lower', 'lowercase' => function_exists('mb_strtolower') ? mb_strtolower($value, 'UTF-8') : strtolower($value),
                'upper', 'uppercase' => function_exists('mb_strtoupper') ? mb_strtoupper($value, 'UTF-8') : strtoupper($value),
                'email' => strtolower(trim($value)),
                'url' => filter_var(trim($value), FILTER_SANITIZE_URL) ?: '',
                'int', 'integer' => (string)((int)filter_var($value, FILTER_SANITIZE_NUMBER_INT)),
                'float', 'number' => (string)((float)filter_var($value, FILTER_SANITIZE_NUMBER_FLOAT, FILTER_FLAG_ALLOW_FRACTION | FILTER_FLAG_ALLOW_SCIENTIFIC)),
                'bool', 'boolean' => $this->sanitizeBool($value),
                'only_digits', 'digits' => preg_replace('/\D+/', '', $value) ?? '',
                'slug' => $this->slug($value),
                'filename' => $this->filename($value),
                'null_if_empty' => $value === '' ? null : $value,
                'max_length' => $this->truncate($value, (int)($param ?? $maxStringLength)),
                default => $value,
            };

            if ($value === null) {
                return null;
            }
        }

        if (is_string($value) && strlen($value) > $maxStringLength) {
            $value = substr($value, 0, $maxStringLength);
        }

        return $value;
    }

    private function sanitizeKey(string $key): string
    {
        $key = preg_replace('/[^A-Za-z0-9_.:-]/', '_', $key) ?? '';
        return trim($key, '._:-');
    }

    private function sanitizeBool(string $value): string
    {
        $bool = filter_var($value, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);
        if ($bool === null) {
            return $value;
        }
        return $bool ? '1' : '0';
    }

    private function slug(string $value): string
    {
        $value = strtolower(trim($value));
        $value = preg_replace('/[^a-z0-9]+/i', '-', $value) ?? '';
        return trim($value, '-');
    }

    private function filename(string $value): string
    {
        $value = basename(str_replace('\\', '/', $value));
        $value = preg_replace('/[^A-Za-z0-9._-]+/', '_', $value) ?? '';
        return trim($value, '._-') ?: 'file';
    }

    private function truncate(string $value, int $max): string
    {
        $max = max(1, $max);
        return strlen($value) > $max ? substr($value, 0, $max) : $value;
    }
}
