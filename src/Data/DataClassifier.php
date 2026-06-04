<?php
namespace Mnb\SecurityCore\Data;

class DataClassifier
{
    public const PUBLIC = 'public';
    public const INTERNAL = 'internal';
    public const CONFIDENTIAL = 'confidential';
    public const SENSITIVE = 'sensitive';
    public const HIGHLY_SENSITIVE = 'highly_sensitive';

    public function __construct(private array $fieldMap = []) {}

    public function classify(string $field): string
    {
        return $this->fieldMap[$field] ?? self::INTERNAL;
    }

    public function isSensitive(string $field): bool
    {
        return in_array($this->classify($field), [self::SENSITIVE, self::HIGHLY_SENSITIVE], true);
    }
}
