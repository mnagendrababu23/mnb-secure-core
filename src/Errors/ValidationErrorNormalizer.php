<?php
namespace Mnb\SecurityCore\Errors;

final class ValidationErrorNormalizer
{
    /** @var array<int,string> */
    private array $blockedPatterns = ['password_hash', 'remember_token', 'api_token', 'private_key', 'secret', 'tenant_internal_id', 'db_', 'sql_', 'internal'];

    public function __construct(private ErrorPolicy $policy) {}

    /** @param array<string,mixed> $errors @return array<string,mixed> */
    public function normalize(array $errors): array
    {
        if (!$this->policy->normalizeValidationFields()) {
            return $errors;
        }
        $out = [];
        foreach ($errors as $field => $messages) {
            $public = $this->publicFieldName((string)$field);
            if ($public === null) {
                continue;
            }
            $out[$public] = $this->normalizeMessages($messages);
        }
        return $out;
    }

    private function publicFieldName(string $field): ?string
    {
        $map = $this->policy->validationFieldMap();
        if (isset($map[$field])) {
            return $map[$field];
        }
        $lower = strtolower($field);
        if ($this->policy->hideInternalValidationFields()) {
            foreach ($this->blockedPatterns as $pattern) {
                if (str_contains($lower, $pattern)) {
                    return null;
                }
            }
        }
        $field = preg_replace('/[^A-Za-z0-9_.-]+/', '_', $field) ?? 'field';
        $field = trim($field, '._-');
        return $field !== '' ? $field : 'field';
    }

    private function normalizeMessages(mixed $messages): mixed
    {
        if (is_array($messages)) {
            return array_map(fn(mixed $message): string => $this->safeMessage($message), array_values($messages));
        }
        return $this->safeMessage($messages);
    }

    private function safeMessage(mixed $message): string
    {
        $text = is_scalar($message) ? (string)$message : 'Invalid value.';
        $text = preg_replace('/\b(?:column|table|sql|database|pdo|tenant_internal_id|password_hash)\b/i', 'field', $text) ?? $text;
        return trim($text) !== '' ? $text : 'Invalid value.';
    }
}
