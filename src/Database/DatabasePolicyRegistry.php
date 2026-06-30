<?php
namespace Mnb\SecurityCore\Database;

use InvalidArgumentException;

final class DatabasePolicyRegistry
{
    /** @var array<string,TableSecurityPolicy> */
    private array $policies = [];

    /** @param array<string,TableSecurityPolicy|array<string,mixed>> $policies */
    public function __construct(array $policies = [])
    {
        foreach ($policies as $name => $policy) {
            if ($policy instanceof TableSecurityPolicy) {
                $this->register((string)$name, $policy);
            } elseif (is_array($policy)) {
                $this->register((string)$name, $this->fromArray((string)$name, $policy));
            }
        }
    }

    public function register(string $name, TableSecurityPolicy $policy): void
    {
        $name = $this->normalizeName($name);
        $this->policies[$name] = $policy;
        $this->policies[$this->normalizeName($policy->resourceType)] = $policy;
        $this->policies[$this->normalizeName($policy->table)] = $policy;
    }

    public function has(string $name): bool
    {
        return isset($this->policies[$this->normalizeName($name)]);
    }

    public function get(string $name): TableSecurityPolicy
    {
        $key = $this->normalizeName($name);
        if (!isset($this->policies[$key])) {
            throw new InvalidArgumentException("Database policy not registered: {$name}");
        }
        return $this->policies[$key];
    }

    /** @return array<string,array<string,mixed>> */
    public function toArray(): array
    {
        $out = [];
        foreach ($this->policies as $name => $policy) {
            $out[$name] = [
                'table' => $policy->table,
                'resource_type' => $policy->resourceType,
                'selectable_columns' => $policy->selectableColumns,
                'insertable_columns' => $policy->insertableColumns,
                'updatable_columns' => $policy->updatableColumns,
                'searchable_columns' => $policy->searchableColumns,
                'orderable_columns' => $policy->orderableColumns,
                'tenant_columns' => $policy->tenantColumns,
                'soft_deletes' => $policy->softDeletes,
            ];
        }
        return $out;
    }

    private function fromArray(string $name, array $policy): TableSecurityPolicy
    {
        return new TableSecurityPolicy(
            table: (string)($policy['table'] ?? $name),
            resourceType: (string)($policy['resource_type'] ?? $policy['resourceType'] ?? $name),
            selectableColumns: array_values((array)($policy['selectable_columns'] ?? $policy['selectableColumns'] ?? [])),
            insertableColumns: array_values((array)($policy['insertable_columns'] ?? $policy['insertableColumns'] ?? [])),
            updatableColumns: array_values((array)($policy['updatable_columns'] ?? $policy['updatableColumns'] ?? [])),
            searchableColumns: array_values((array)($policy['searchable_columns'] ?? $policy['searchableColumns'] ?? [])),
            orderableColumns: array_values((array)($policy['orderable_columns'] ?? $policy['orderableColumns'] ?? [])),
            primaryKey: (string)($policy['primary_key'] ?? $policy['primaryKey'] ?? 'id'),
            tenantColumns: (array)($policy['tenant_columns'] ?? $policy['tenantColumns'] ?? []),
            softDeletes: (bool)($policy['soft_deletes'] ?? $policy['softDeletes'] ?? true),
            deletedAtColumn: (string)($policy['deleted_at_column'] ?? $policy['deletedAtColumn'] ?? 'deleted_at'),
            sensitiveColumns: array_values((array)($policy['sensitive_columns'] ?? $policy['sensitiveColumns'] ?? [])),
            hiddenColumns: array_values((array)($policy['hidden_columns'] ?? $policy['hiddenColumns'] ?? [])),
            maskedColumns: array_values((array)($policy['masked_columns'] ?? $policy['maskedColumns'] ?? [])),
            permissionColumns: (array)($policy['permission_columns'] ?? $policy['permissionColumns'] ?? [])
        );
    }

    private function normalizeName(string $name): string
    {
        $name = strtolower(trim($name));
        if ($name === '' || !preg_match('/^[a-z0-9][a-z0-9_.:-]{0,127}$/', $name)) {
            throw new InvalidArgumentException('Database policy name must be a safe identifier.');
        }
        return $name;
    }
}
