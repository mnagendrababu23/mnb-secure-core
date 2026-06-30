<?php
namespace Mnb\SecurityCore\Trust;

class TrustBoundaryPolicy
{
    /** @param list<string> $zones @param list<string> $dataClasses @param list<string> $actions @param list<string> $resources @param list<string> $permissions @param list<string> $scopes @param list<string> $roles */
    public function __construct(
        private string $name,
        private array $zones,
        private array $dataClasses,
        private array $actions,
        private array $resources = [],
        private array $permissions = [],
        private array $scopes = [],
        private array $roles = [],
        private bool $tenantRequired = false,
        private bool $audit = false,
        private string $denyMessage = 'Trust boundary denied'
    ) {
        self::assertSafeName($name, 'policy name');
        $this->zones = self::normalizeList($zones);
        $this->dataClasses = self::normalizeList($dataClasses);
        $this->actions = self::normalizeList($actions);
        $this->resources = self::normalizeList($resources);
        $this->permissions = self::normalizeList($permissions);
        $this->scopes = self::normalizeList($scopes);
        $this->roles = self::normalizeList($roles);

        if ($this->zones === [] || $this->dataClasses === [] || $this->actions === []) {
            throw new \InvalidArgumentException('Trust boundary policies require zones, data classes, and actions.');
        }
    }

    /** @param array<string,mixed> $config */
    public static function fromArray(string $name, array $config): self
    {
        return new self(
            $name,
            self::listFromConfig($config['zones'] ?? []),
            self::listFromConfig($config['data_classes'] ?? []),
            self::listFromConfig($config['actions'] ?? []),
            self::listFromConfig($config['resources'] ?? []),
            self::listFromConfig($config['permissions'] ?? []),
            self::listFromConfig($config['scopes'] ?? []),
            self::listFromConfig($config['roles'] ?? []),
            (bool)($config['tenant_required'] ?? false),
            (bool)($config['audit'] ?? false),
            is_scalar($config['deny_message'] ?? null) ? (string)$config['deny_message'] : 'Trust boundary denied'
        );
    }

    public function name(): string { return $this->name; }
    /** @return list<string> */ public function zones(): array { return $this->zones; }
    /** @return list<string> */ public function dataClasses(): array { return $this->dataClasses; }
    /** @return list<string> */ public function actions(): array { return $this->actions; }
    /** @return list<string> */ public function resources(): array { return $this->resources; }
    /** @return list<string> */ public function permissions(): array { return $this->permissions; }
    /** @return list<string> */ public function scopes(): array { return $this->scopes; }
    /** @return list<string> */ public function roles(): array { return $this->roles; }
    public function tenantRequired(): bool { return $this->tenantRequired; }
    public function audit(): bool { return $this->audit; }
    public function denyMessage(): string { return $this->denyMessage; }

    public function allowsZone(string $zone): bool { return in_array($zone, $this->zones, true) || in_array('*', $this->zones, true); }
    public function allowsDataClass(string $dataClass): bool { return in_array($dataClass, $this->dataClasses, true) || in_array('*', $this->dataClasses, true); }
    public function allowsAction(string $action): bool { return in_array($action, $this->actions, true) || in_array('*', $this->actions, true); }
    public function allowsResource(?string $resource): bool { return $this->resources === [] || $resource === null || in_array($resource, $this->resources, true) || in_array('*', $this->resources, true); }

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        return [
            'name' => $this->name,
            'zones' => $this->zones,
            'data_classes' => $this->dataClasses,
            'actions' => $this->actions,
            'resources' => $this->resources,
            'permissions' => $this->permissions,
            'scopes' => $this->scopes,
            'roles' => $this->roles,
            'tenant_required' => $this->tenantRequired,
            'audit' => $this->audit,
            'deny_message' => $this->denyMessage,
        ];
    }

    /** @return list<string> */
    private static function listFromConfig(mixed $value): array
    {
        if (is_string($value)) {
            $value = array_filter(array_map('trim', explode(',', $value)));
        }
        return is_array($value) ? self::normalizeList($value) : [];
    }

    /** @param array<int|string,mixed> $values @return list<string> */
    private static function normalizeList(array $values): array
    {
        $out = [];
        foreach ($values as $value) {
            if (!is_scalar($value)) {
                continue;
            }
            $item = trim((string)$value);
            if ($item !== '') {
                $out[] = $item;
            }
        }
        return array_values(array_unique($out));
    }

    public static function assertSafeName(string $name, string $label = 'name'): void
    {
        if (!preg_match('/^[a-z][a-z0-9_.:-]{1,95}$/', $name)) {
            throw new \InvalidArgumentException("Trust boundary {$label} must be a safe slug.");
        }
    }
}
