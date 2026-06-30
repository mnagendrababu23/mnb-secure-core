<?php
namespace Mnb\SecurityCore\Authorization;

class AuthorizationPolicy
{
    /** @param list<string> $actions @param list<string> $roles @param list<string> $permissions @param list<string> $scopes @param list<string> $dataClasses @param array<string,mixed> $fields */
    public function __construct(
        private string $name,
        private ?string $resource = null,
        private array $actions = ['access'],
        private array $roles = [],
        private array $permissions = [],
        private array $scopes = [],
        private bool $tenantRequired = false,
        private array $dataClasses = [],
        private ?string $trustBoundary = null,
        private bool $audit = false,
        private array $fields = [],
        private string $denyMessage = 'Access denied'
    ) {
        self::assertSafeName($name, 'authorization policy name');
        $this->resource = $resource !== null && trim($resource) !== '' ? trim($resource) : null;
        $this->actions = self::normalizeList($actions) ?: ['access'];
        $this->roles = self::normalizeList($roles);
        $this->permissions = self::normalizeList($permissions);
        $this->scopes = self::normalizeList($scopes);
        $this->dataClasses = self::normalizeList($dataClasses);
        $this->trustBoundary = $trustBoundary !== null && trim($trustBoundary) !== '' ? trim($trustBoundary) : null;
    }

    /** @param array<string,mixed> $config */
    public static function fromArray(string $name, array $config): self
    {
        return new self(
            $name,
            isset($config['resource']) && is_scalar($config['resource']) ? (string)$config['resource'] : null,
            self::listFromConfig($config['actions'] ?? []),
            self::listFromConfig($config['roles'] ?? []),
            self::listFromConfig($config['permissions'] ?? []),
            self::listFromConfig($config['scopes'] ?? []),
            (bool)($config['tenant_required'] ?? false),
            self::listFromConfig($config['data_classes'] ?? []),
            isset($config['trust_boundary']) && is_scalar($config['trust_boundary']) && trim((string)$config['trust_boundary']) !== '' ? (string)$config['trust_boundary'] : null,
            (bool)($config['audit'] ?? false),
            is_array($config['fields'] ?? null) ? $config['fields'] : [],
            is_scalar($config['deny_message'] ?? null) ? (string)$config['deny_message'] : 'Access denied'
        );
    }

    public function name(): string { return $this->name; }
    public function resource(): ?string { return $this->resource; }
    /** @return list<string> */ public function actions(): array { return $this->actions; }
    /** @return list<string> */ public function roles(): array { return $this->roles; }
    /** @return list<string> */ public function permissions(): array { return $this->permissions; }
    /** @return list<string> */ public function scopes(): array { return $this->scopes; }
    public function tenantRequired(): bool { return $this->tenantRequired; }
    /** @return list<string> */ public function dataClasses(): array { return $this->dataClasses; }
    public function trustBoundary(): ?string { return $this->trustBoundary; }
    public function audit(): bool { return $this->audit; }
    /** @return array<string,mixed> */ public function fields(): array { return $this->fields; }
    public function denyMessage(): string { return $this->denyMessage; }

    public function allowsAction(string $action): bool { return in_array('*', $this->actions, true) || in_array($action, $this->actions, true); }
    public function allowsResource(?string $resource): bool { return $this->resource === null || $resource === null || $this->resource === '*' || $this->resource === $resource; }
    public function allowsDataClass(?string $class): bool { return $this->dataClasses === [] || $class === null || in_array('*', $this->dataClasses, true) || in_array($class, $this->dataClasses, true); }

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        return [
            'name' => $this->name,
            'resource' => $this->resource,
            'actions' => $this->actions,
            'roles' => $this->roles,
            'permissions' => $this->permissions,
            'scopes' => $this->scopes,
            'tenant_required' => $this->tenantRequired,
            'data_classes' => $this->dataClasses,
            'trust_boundary' => $this->trustBoundary,
            'audit' => $this->audit,
            'fields' => $this->fields,
            'deny_message' => $this->denyMessage,
        ];
    }

    /** @return list<string> */
    private static function listFromConfig(mixed $value): array
    {
        if (is_string($value)) { $value = array_filter(array_map('trim', explode(',', $value))); }
        return is_array($value) ? self::normalizeList($value) : [];
    }

    /** @param array<int|string,mixed> $values @return list<string> */
    private static function normalizeList(array $values): array
    {
        $out = [];
        foreach ($values as $value) {
            if (!is_scalar($value)) { continue; }
            $item = trim((string)$value);
            if ($item !== '') { $out[] = $item; }
        }
        return array_values(array_unique($out));
    }

    public static function assertSafeName(string $name, string $label = 'name'): void
    {
        if (!preg_match('/^[a-z][a-z0-9_.:-]{1,95}$/', $name)) {
            throw new \InvalidArgumentException("{$label} must be a safe slug.");
        }
    }
}
