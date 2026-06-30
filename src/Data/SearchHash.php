<?php
namespace Mnb\SecurityCore\Data;

class SearchHash
{
    public function __construct(private string $key, private string $prefix = 'mnb:search')
    {
        if (strlen($key) < 32) {
            throw new \InvalidArgumentException('Search hash key must be at least 32 characters.');
        }
    }

    public function hash(string $resource, string $field, mixed $value): string
    {
        $normalized = $this->normalize($value);
        $context = $this->prefix . '|' . $resource . '|' . $field;
        return hash_hmac('sha256', $context . '|' . $normalized, $this->key);
    }

    public function normalize(mixed $value): string
    {
        if (is_bool($value)) {
            return $value ? 'true' : 'false';
        }
        if ($value === null) {
            return '';
        }
        if (is_array($value) || is_object($value)) {
            return strtolower(trim(json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) ?: ''));
        }
        return strtolower(trim((string)$value));
    }
}
