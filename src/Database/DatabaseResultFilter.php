<?php
namespace Mnb\SecurityCore\Database;

use Mnb\SecurityCore\Authz\TenantContext;

final class DatabaseResultFilter
{
    public function __construct(private DatabaseFieldProtection $fieldProtection = new DatabaseFieldProtection()) {}

    public static function fromConfig(array $config): self
    {
        return new self(DatabaseFieldProtection::fromConfig($config));
    }

    /** @param array<int,array<string,mixed>> $rows @return array<int,array<string,mixed>> */
    public function filterRows(TenantContext $context, TableSecurityPolicy $policy, array $rows): array
    {
        if (!$this->fieldProtection->enabled) {
            return $rows;
        }
        return array_map(fn(array $row): array => $this->filterRow($context, $policy, $row), $rows);
    }

    /** @param array<string,mixed>|null $row @return array<string,mixed>|null */
    public function filterOne(TenantContext $context, TableSecurityPolicy $policy, ?array $row): ?array
    {
        return $row === null ? null : $this->filterRow($context, $policy, $row);
    }

    /** @param array<string,mixed> $row @return array<string,mixed> */
    public function filterRow(TenantContext $context, TableSecurityPolicy $policy, array $row): array
    {
        foreach (array_keys($row) as $column) {
            if ($this->fieldProtection->shouldHide((string)$column, $policy)) {
                unset($row[$column]);
                continue;
            }
            $permission = $policy->permissionColumns[$column] ?? null;
            if (is_string($permission) && $permission !== '' && !in_array($permission, $context->permissions, true) && !in_array('super_admin', $context->roles, true)) {
                unset($row[$column]);
                continue;
            }
            if ($this->fieldProtection->shouldMask((string)$column, $policy) && !in_array($policy->resourceType . '.view_sensitive', $context->permissions, true) && !in_array('super_admin', $context->roles, true)) {
                $row[$column] = $this->mask($row[$column]);
            }
        }
        return $row;
    }

    private function mask(mixed $value): mixed
    {
        if ($value === null || $value === '') {
            return $value;
        }
        $value = (string)$value;
        if (str_contains($value, '@')) {
            [$local, $domain] = array_pad(explode('@', $value, 2), 2, '');
            return substr($local, 0, 1) . str_repeat('*', max(2, strlen($local) - 1)) . '@' . $domain;
        }
        $len = strlen($value);
        if ($len <= 4) {
            return str_repeat('*', $len);
        }
        return substr($value, 0, 2) . str_repeat('*', max(2, $len - 4)) . substr($value, -2);
    }
}
