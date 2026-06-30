<?php
namespace Mnb\SecurityCore\Data;

class DataProtectionPolicy
{
    /** @var array<string,ProtectedField> */
    private array $fields;

    /** @param array<string,ProtectedField> $fields @param array<string,mixed> $config */
    public function __construct(
        private string $resource,
        private string $defaultClass = DataClassifier::INTERNAL,
        private bool $tenantScoped = false,
        array $fields = [],
        private array $config = []
    ) {
        if (!preg_match('/^[A-Za-z_][A-Za-z0-9_:-]*$/', $resource)) {
            throw new \InvalidArgumentException('Data protection resource name must be safe.');
        }
        $this->fields = $fields;
    }

    /** @param array<string,mixed> $config */
    public static function fromArray(string $resource, array $config): self
    {
        $fields = [];
        foreach ((array)($config['fields'] ?? []) as $name => $fieldConfig) {
            if (!is_string($name)) { continue; }
            $fields[$name] = ProtectedField::fromConfig($name, is_array($fieldConfig) || is_string($fieldConfig) ? $fieldConfig : []);
        }
        return new self(
            $resource,
            (string)($config['default_class'] ?? $config['data_class'] ?? DataClassifier::INTERNAL),
            (bool)($config['tenant_scoped'] ?? false),
            $fields,
            $config
        );
    }

    public function resource(): string { return $this->resource; }
    public function defaultClass(): string { return $this->defaultClass; }
    public function tenantScoped(): bool { return $this->tenantScoped; }

    /** @return array<string,ProtectedField> */
    public function fields(): array { return $this->fields; }

    public function field(string $name): ProtectedField
    {
        return $this->fields[$name] ?? new ProtectedField($name, $this->defaultClass);
    }

    public function hasField(string $name): bool
    {
        return isset($this->fields[$name]);
    }

    /** @return array<string,mixed> */
    public function config(): array { return $this->config; }
}
