<?php
namespace Mnb\SecurityCore\Data;

class ProtectedField
{
    public const CLASSES = [
        DataClassifier::PUBLIC,
        DataClassifier::INTERNAL,
        DataClassifier::CONFIDENTIAL,
        DataClassifier::SENSITIVE,
        DataClassifier::HIGHLY_SENSITIVE,
    ];

    /** @param array<string,mixed> $config */
    public function __construct(
        public readonly string $name,
        public readonly string $classification = DataClassifier::INTERNAL,
        public readonly bool $encrypt = false,
        public readonly bool $searchHash = false,
        public readonly string|false|null $mask = null,
        public readonly bool $read = true,
        public readonly bool $write = true,
        public readonly bool|string $export = true,
        public readonly bool $log = true,
        public readonly array $config = []
    ) {
        if (!preg_match('/^[A-Za-z_][A-Za-z0-9_.:-]*$/', $name)) {
            throw new \InvalidArgumentException('Protected field name must be safe.');
        }
        if (!in_array($classification, self::CLASSES, true)) {
            throw new \InvalidArgumentException('Protected field classification is invalid.');
        }
    }

    /** @param array<string,mixed>|string $config */
    public static function fromConfig(string $name, array|string $config): self
    {
        if (is_string($config)) {
            $config = ['class' => $config];
        }
        $class = (string)($config['class'] ?? $config['classification'] ?? DataClassifier::INTERNAL);
        $mask = $config['mask'] ?? null;
        if ($mask !== false && $mask !== null) {
            $mask = (string)$mask;
        }
        return new self(
            $name,
            $class,
            (bool)($config['encrypt'] ?? false),
            (bool)($config['search_hash'] ?? $config['searchHash'] ?? false),
            $mask,
            (bool)($config['read'] ?? true),
            (bool)($config['write'] ?? true),
            $config['export'] ?? true,
            (bool)($config['log'] ?? true),
            $config
        );
    }

    public function hashFieldName(): string
    {
        return $this->name . '_hash';
    }
}
